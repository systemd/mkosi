# TODO

* volatile images

* work on device nodes

* mkosi --all (for building everything in mkosi.files/)

* --architecture= is chaos: we need to define a clear vocabulary of
  architectures that can deal with the different names of
  architectures in debian, fedora and uname.

* squashfs root images with /home and /srv on ext4

* optionally output the root partition (+ verity) and the unified
  kernel image as additional artifacts, so that they can be used in
  automatic updating schemes (i.e. take an old image that is currently
  in use, add a root partition with the new root image (+ verity), and
  drop the new kernel into the ESP, and an update is complete.

* minimization with gpt_btrfs doesn't seem to take fs compression into
  account. The resulting device is half-empty.

* --format gpt_mksquashfs --minimize throws an error. It should just
  silently ignore --minimize, since it's implied.

* --debug=help should list known options and exit. Same for other
  options which accept a fixed list of choices.
