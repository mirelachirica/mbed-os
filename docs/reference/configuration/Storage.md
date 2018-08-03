<h2 id="configuration-storage">Storage</h2>

This page describes the build-time configurable parameters for storage in Mbed OS. There are no standard shared configuration options for different storage module. Instead, each module has its own implementation-specific set of configuration options.

- [LittleFS configuration](#littlefs-configuration).
- [NVStore configuration](#nvstore-configuration).

The following is the complete list of storage configuration parameters, as generated by `mbed compile --config -v`. Please see [the configuration system documentation](/docs/development/reference/configuration.html) for details on how you may use or override these settings.

#### LittleFS configuration

LittleFS provides several configuration options that you can use to tweak the performance of the file system on different hardware. By default, this file system finds the optimal configuration from the underlying block device's geometry, but you can override this to optimize special situations. For example, if your device has a large amount of RAM, you can increase the `read_size` and `prog_size` configuration options for a minor speed improvement.

Note that LittleFS has 4 levels of debug logging. By default, all logging is enabled except for `enable_debug`. Setting `enable_debug` to `true` makes the log output very verbose, and the output is useful for bug reports.

```
Configuration parameters
------------------------

Name: littlefs.block_size
    Description: Size of an erasable block. This does not impact ram consumption and may be larger than the physical erase size. However, this should be kept small as each file currently takes up an entire block.
    Defined by: library:littlefs
    Macro name: MBED_LFS_BLOCK_SIZE
    Value: 512 (set by library:littlefs)
Name: littlefs.prog_size
    Description: Minimum size of a block program. This determines the size of program buffers. This may be larger than the physical program size to improve performance by caching more of the block device.
    Defined by: library:littlefs
    Macro name: MBED_LFS_PROG_SIZE
    Value: 64 (set by library:littlefs)
Name: littlefs.read_size
    Description: Minimum size of a block read. This determines the size of read buffers. This may be larger than the physical read size to improve performance by caching more of the block device.
    Defined by: library:littlefs
    Macro name: MBED_LFS_READ_SIZE
    Value: 64 (set by library:littlefs)
Name: littlefs.lookahead
    Description: Number of blocks to lookahead during block allocation. A larger lookahead reduces the number of passes required to allocate a block. The lookahead buffer requires only 1 bit per block so it can be quite large with little ram impact. Should be a multiple of 32.
    Defined by: library:littlefs
    Macro name: MBED_LFS_LOOKAHEAD
    Value: 512 (set by library:littlefs)
Name: littlefs.intrinsics
    Description: Enable intrinsics for bit operations such as ctz, popc, and le32 conversion. Can be disabled to help debug toolchain issues
    Defined by: library:littlefs
    Macro name: MBED_LFS_INTRINSICS
    Value: 1 (set by library:littlefs)
Name: littlefs.enable_assert
    Description: Enables asserts, true = enabled, false = disabled, null = disabled only in release builds
    Defined by: library:littlefs
    No value set
Name: littlefs.enable_debug
    Description: Enables debug logging, true = enabled, false = disabled, null = disabled only in release builds
    Defined by: library:littlefs
    No value set
Name: littlefs.enable_error
    Description: Enables error logging, true = enabled, false = disabled, null = disabled only in release builds
    Defined by: library:littlefs
    No value set
Name: littlefs.enable_info
    Description: Enables info logging, true = enabled, false = disabled, null = disabled only in release builds
    Defined by: library:littlefs
    No value set
Name: littlefs.enable_warn
    Description: Enables warn logging, true = enabled, false = disabled, null = disabled only in release builds
    Defined by: library:littlefs
    No value set
```

#### NVStore configuration

NVStore does not need much configuration. It relies only on the regions of internal flash specified in the `area_*_address` and `area_*_size` for the two areas. Additionally, you can use `max_keys` to manage the amount of RAM NVStore keys needs. Note that `max_keys` defaults to the number of keys Mbed OS needs. You only need to modify it if an application uses NVStore directly.

```
Configuration parameters
------------------------

Name: nvstore.area_1_address
    Description: Area 1 address
    Defined by: library:nvstore
    No value set
Name: nvstore.area_1_size
    Description: Area 1 size
    Defined by: library:nvstore
    No value set
Name: nvstore.area_2_address
    Description: Area 2 address
    Defined by: library:nvstore
    No value set
Name: nvstore.area_2_size
    Description: Area 2 size
    Defined by: library:nvstore
    No value set
Name: nvstore.max_keys
    Description: Maximal number of allowed NVStore keys
    Defined by: library:nvstore
    Macro name: NVSTORE_MAX_KEYS
    Value: 16 (set by library:nvstore)
```