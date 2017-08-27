#!/bin/bash

usage() {
	cat <<-EOF
	Usage: $SCRIPT USERNAME [GROUP]

	  USERNAME: The user to run the service as
	  GROUP: The group to run the service as. If not specified, it will be the same as USERNAME
	EOF
}

SCRIPT="$(readlink -f "$0")"
DIR="$(dirname "$SCRIPT")"
SYNCSCRIPT="$DIR/sync.py"
USERNAME="$1"
GROUP="${2:-$USERNAME}"

if ! [[ $USERNAME ]] || ! [[ $GROUP ]]; then
	echo "You must provide a user/group to install the systemd service/timer"
	usage
	exit 1
fi

cd "$DIR"

pip install -r requirements.txt

for servicefile in mediaserver-stack-syncer.timer mediaserver-stack-syncer.service; do
	sed -e "s|__SCRIPT__|$SYNCSCRIPT -vv|g" \
		-e "s|__USER__|$USERNAME|g" \
		-e "s|__GROUP__|$GROUP|g" \
		> /etc/systemd/system/$servicefile < $servicefile
done

systemctl enable mediaserver-stack-syncer.timer
systemctl restart mediaserver-stack-syncer.timer mediaserver-stack-syncer.service
