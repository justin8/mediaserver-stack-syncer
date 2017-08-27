# mediaserver-stack-syncer
This is designed to be able to sync a variety of TV/movie libraries to support a sometimes-online storage server while running a couchpotato/sonnarr/etc stack. 

## Usage:
Coming soon!

## Known Issues
* Some filenames with certain UTF-8 characters may result in them not being removed from the remote (downloader) system due to how python handles these strings. e.g. `K   r   o 314 210   d       M   a 314 210   n   d   o   o   n` becomes `K   r 303 266   d       M 303 244   n   d   o   o   n`
