# AutoStream
A kernel module to tag stream ID to Linux block I/O requests using AutoStream (original paper: https://dl.acm.org/doi/10.1145/3078468.3078469. Currently only SFR is implemented). 

To compile and install this module as a Linux Kernel module, just run `make`. 

Before loading the kernel module, please check if your SSD supports stream and your OS has enabled stream capability as described in the first two sections of this README. For the usage of the kernel module, see "**Enable the Kernel Module and Assign Parameters to Module**" and "**Change Kernel Module Parameters On-the-fly**".

If you are looking for an implementation for tagging Multistream IDs to applications, see https://github.com/zhxq/Multistream.

This kernel module is used for the Evaluation section of the paper _Excessive SSD-Internal Parallelism Considered Harmful_ (https://dl.acm.org/doi/abs/10.1145/3599691.3603412). Please consider citing our paper if you use this kernel module in your paper. Thank you!

## Check directory setting
`sudo nvme dir-receive /dev/nvme0n1 -D 1 -O 1 -H`

-D is type and -O is operation. Both = 1 will ask for stream support of this controller (defined in NVMe protocol). -H is to make the result human readable. This can show if the SSD has stream support and maximum number of streams supported by the SSD.


## Enable stream support for Linux Kernel NVMe driver

This is to enable the stream capability in Linux Kernel.

 - Edit /etc/default/grub, add "nvme_core.streams=1" to `GRUB_CMDLINE_LINUX`.
 - Run `sudo update-grub` to update grub settings.
 - Reboot.

## Enable the Kernel Module and Assign Parameters to Module

`sudo modprobe autostream disk_list="disk0n1:1048576:4096:5:16;disk1n1:16777216:8192:7:32"`

The kernel module accepts a parameter, namely "disk_list", as a list of disks to apply AutoStream, and parameters for the disk.

In this example, it will set parameter `disk_list` of `autostream` module to "disk0n1:1048576:4096:5:16;disk1n1:16777216:8192:7:32", which asks the kernel module to apply AutoStream on disk0n1 and disk1n1, where size of disk0n1 is 1048576 bytes, one chunk per 4096 bytes on disk, decay period as 5s, and 16 streams supported by disk0n1 - similar goes to disk1n1. You can add more than two disks - use semicolons to separate their information.

You can add more than 4 streams, though Linux Kernel supports at most four streams. We have circumvented this limitation in the kernel module.

## Change Kernel Module Parameters On-the-fly

If you have already loaded the kernel module, but want to change the parameters passed into the kernel module, you can use the following command:

`echo "disk0n1:1048576:4096:5:16;disk1n1:16777216:8192:7:32" | sudo tee /sys/module/autostream/parameters/disk_list`

This will set parameter `disk_list` of module `autostream` to "disk0n1:1048576:4096:5:16;disk1n1:16777216:8192:7:32".
