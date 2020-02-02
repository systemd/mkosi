# TODO

* volatile images

* work on device nodes

* allow passing env vars

* --architecture= is chaos: we need to define a clear vocabulary of
  architectures that can deal with the different names of
  architectures in debian, fedora and uname.

* squashfs root images with /home and /srv on ext4

* optionally output the root partition (+ verity) and the unified
  kernel image as additional artifacts, so that they can be used in
  automatic updating schemes (i.e. take an old image that is currently
  in use, add a root partition with the new root image (+ verity), and
  drop the new kernel into the ESP, and an update is complete.
