# python-patcher
Python command line IPS patcher. Creates and applies IPS patches.

For now, this software is slow to create patches and does not optimize the
created patches with RLE encoding, so it sucks. But it works and the code is
small and very readable :) If you want one that does not suck, use
[Flips](https://github.com/Alcaro/Flips).

## usage
For help:

    $ patcher.py [command] -h

### apply
To apply a patch to *in_file* and save the result to *out_file*

    $ patcher.py apply patch_file in_file out_file

### create
To create a patch with the changes from *original_file* to *modified_file* and
save it to *out_file*

    $ patcher.py create original_file modified_file out_file
