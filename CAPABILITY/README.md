Docs:
* https://elixir.bootlin.com/linux/v4.15.2/source/include/uapi/linux/capability.h
* https://elixir.bootlin.com/linux/v4.15.2/source/security/selinux/include/classmap.h

Steps: 
* Symlink (and replace) `capability.h` file to `/path/to/kernel/include/uapi/linux/capability.h`
* Symlink (and replace) `classmap.h` file to `/path/to/kernel/security/selinux/include/classmap.h`

Example (in CAPABILITY project directory):
* `ln -fs `pwd`/capability.h /path/to/kernel/include/uapi/linux/capability.h`
* `ln -fs `pwd`/classmap.h /path/to/kernel/security/selinux/include/classmap.h`

Rebuild and Reinstall Kernel... (in Kernel Directory):
* `make -j $(nproc)`
* `sudo make -j $(nproc) INSTALL_MOD_STRIP=1 modules_install`
* `sudo make -j $(nproc) install`
* `sudo reboot -h now`