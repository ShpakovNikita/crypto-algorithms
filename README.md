# crypto-algorithms
Different popular cryptography algorithms

### How to build?
Currently, project supports only Windows and Macos platforms, but it also can be easily configured for Linux.

### Macos
```
$ mkdir build
$ cd build
$ CMake -G Xcode ..
```

And then you can select needed algorithm via `Product`->`Scheme`->`Choose scheme`

### Windows (Using VS generator)
```
$ CMake -G "Visual Studio 16 2019"
```

And then you can select needed algorithm in project explorer, right click, `Set as StartUp project`
