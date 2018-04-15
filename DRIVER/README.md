Prerequesites
* Make sure you have Kernel Compiled and Installed with Modules
* `make -j $(nproc)` on kernel dir
* `sudo make -j $(nproc) INSTALL_MOD_STRIP=1 modules_install` on kernel dir 
* `sudo make -j $(nproc) install` on kernel dir

Usage and Compiling
* `make` to compile
* `sudo insmod char.ko` to enable module
  * `sudo chmod a+rw /dev/<DEVICE_NAME>` to be able to use (no need with latest code)
  * `sudo chmod a+rw /dev/secret412*`
* `sudo rmmod char.ko` to remove module

