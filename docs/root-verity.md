# Operating disk images with verity protected root partition

First of all, to build a disk image with a verity protected root
partition, put the following in mkosi.repart:

```conf
# mkosi.repart/00-esp.conf
[Partition]
CopyFiles=/efi:/
CopyFiles=/boot:/
Format=vfat
SizeMinBytes=1024M
Type=esp

# mkosi.repart/10-root.conf
[Partition]
CopyFiles=/
ExcludeFilesTarget=/var/
Format=erofs
Label=%M_%A_root
Minimize=yes
SplitName=%t.%U
Type=root
Verity=data
VerityMatchKey=root

# mkosi.repart/11-root-verity.conf
[Partition]
Label=%M_%A_verity
Minimize=yes
SplitName=%t.%U
Type=root-verity
Verity=hash
VerityMatchKey=root

# mkosi.repart/12-root-verity-sig.conf
[Partition]
Label=%M_%A_verity_sig
SplitName=%t.%U
Type=root-verity-sig
Verity=signature
VerityMatchKey=root
```

Then, you'll need a dropin for systemd-repart in the initrd to make sure
it runs after the root partition has been mounted, so let's create an
initrd with `mkosi.images` where we customize systemd-repart to behave
like this:

```conf
# mkosi.images/initrd/mkosi.conf
[Include]
Include=mkosi-initrd

# mkosi.images/initrd/mkosi.extra/usr/lib/systemd/system/systemd-repart.service.d/sysroot.conf
[Unit]
After=sysroot.mount
ConditionDirectoryNotEmpty=|/sysroot/usr/lib/repart.d
```

Finally, we'll need some partition definitions in the image itself to
create an A/B update setup and an encrypted `/var`. This includes the
definitions from mkosi.repart in a reduced form solely for matching the
existing partitions:

```conf
# mkosi.extra/usr/lib/repart.d/00-esp.conf
[Partition]
Type=esp

# mkosi.extra/usr/lib/repart.d/10-root.conf
[Partition]
Label=%M_%A
Type=root

# mkosi.extra/usr/lib/repart.d/11-root-verity.conf
[Partition]
Label=%M_%A_verity
Type=root-verity

# mkosi.extra/usr/lib/repart.d/12-root-verity-sig.conf
[Partition]
Label=%M_%A_verity_sig
Type=root-verity-sig

# mkosi.extra/usr/lib/repart.d/20-root.conf
[Partition]
Label=_empty
SizeMaxBytes=2048M
SizeMinBytes=2048M
Type=root

# mkosi.extra/usr/lib/repart.d/21-root-verity.conf
[Partition]
Label=_empty
SizeMaxBytes=300M
SizeMinBytes=300M
Type=root-verity

# mkosi.extra/usr/lib/repart.d/22-root-verity-sig.conf
[Partition]
Label=_empty
Type=root-verity-sig

# mkosi.extra/usr/lib/repart.d/30-swap.conf
[Partition]
Type=swap
SizeMinBytes=4G
SizeMaxBytes=4G

# mkosi.extra/usr/lib/repart.d/40-var.conf
[Partition]
Type=var
Format=ext4
Encrypt=tpm2
SizeMinBytes=2G
```

Because in this setup `/etc` is immutable, we have to embed the machine
ID in the image itself at build time so let's generate a machine ID and
persist it by running `systemd-id128 new >mkosi.machine-id`. The machine
ID is required as it is embedded in the `/var` partition UUID and
systemd will refuse to mount a `/var` partition without the machine ID
embedded in its UUID.

You'll then also need some `systemd-sysupdate` definitions in
`/usr/lib/sysupdate.d` which describe how to update the image. These
will differ depending on how the image is updated but we list some
example definitions here. These are all missing a `[Source]` section
whose contents will depend on how updates are deployed:

```conf
# /usr/lib/sysupdate.d/10-root.conf

[Transfer]
ProtectVersion=%A

[Target]
Type=partition
Path=auto
MatchPattern=ParticleOS_@v
MatchPartitionType=root
PartitionFlags=0
ReadOnly=1

# /usr/lib/sysupdate.d/10-root-verity.conf
[Transfer]
ProtectVersion=%A

[Target]
Type=partition
Path=auto
MatchPattern=%M_@v_verity
MatchPartitionType=root-verity
PartitionFlags=0
ReadOnly=1

# /usr/lib/sysupdate.d/12-root-verity-sig.conf
[Transfer]
ProtectVersion=%A

[Target]
Type=partition
Path=auto
MatchPattern=%M_@v_verity_sig
MatchPartitionType=root-verity-sig
PartitionFlags=0
ReadOnly=1

# /usr/lib/sysupdate.d/20-uki.conf
[Transfer]
ProtectVersion=%A

[Target]
Type=regular-file
Path=/EFI/Linux
PathRelativeTo=boot
MatchPattern=%M_@v+@l-@d.efi \
             %M_@v+@l.efi \
             %M_@v.efi
Mode=0444
TriesLeft=3
TriesDone=0
InstancesMax=2
```
