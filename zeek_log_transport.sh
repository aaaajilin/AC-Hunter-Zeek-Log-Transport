#!/bin/bash

#Version 0.5.0 (Modified for Malcolm + AC-Hunter integration)
#Based on AC-Hunter official zeek_log_transport.sh v0.4.1

#This sends any bro/zeek logs less than three days old to the rita/aihunter server. 
#Any logs that already exist on the target system are not retransferred.
#
#Modifications from original:
#  - Excludes 'current' directory from transfer
#  - Flattens directory structure with date prefix (e.g., 2026-01-25_conn.log.gz)
#  - Compatible with RITA rolling import (requires flat structure)

#Before using this, run these on the rita/aihunter server (use zeek in place of bro if necesssary):
#sudo adduser dataimport
#sudo passwd dataimport
#sudo mkdir -p /opt/bro/remotelogs/ /home/dataimport/.ssh/
#add the dataimport user's ssh public key to /home/dataimport/.ssh/authorized_keys in the rita/aihunter server
#sudo chown -R dataimport /opt/bro/remotelogs/ /home/dataimport/.ssh/
#sudo chmod go-rwx -R /home/dataimport/.ssh/

export PATH="/sbin:/usr/sbin:$PATH"		#Note that cron does _NOT_ include /sbin in the path, so attempts to locate the "ip" binary fail without this fix

default_user_on_aihunter='dataimport'
staging_base_dir='/tmp/zeek_transport_staging'


can_ssh () {
	#Test that we can reach the target system over ssh.
	success_code=1
	if [ "$1" = "127.0.0.1" ]; then
		success_code=0
	elif [ -n "$1" ]; then
		token="$RANDOM.$RANDOM"
		if [ "$2" = "-o" -a "$3" = 'PasswordAuthentication=no' ]; then
			status "Attempting to verify that we can ssh to $1"
		else
			status "Attempting to verify that we can ssh to $@ - you may need to provide a password to access this system."
		fi
		ssh_out=`ssh "$@" '/bin/echo '"$token"`
		if [ "$token" = "$ssh_out" ]; then
			#status "successfully connected to $@"
			success_code=0
		#else
			#status "cannot connect to $@"
		fi
	else
		fail "Please supply an ssh target as a command line parameter to can_ssh"
	fi

	return $success_code
}


fail () {
	echo "$@ , exiting." >&2
	exit 1
}


status () {
	echo "==== $@"
}


usage () {
	cat <<HEREDOC >&2
Usage: $0 [--all] [--dest where_to_ssh] [--localdir /local/top/dir/] [--remotedir /remote/top/dir/] [--rsyncparams '--aparam --anotherparam']

Options:
    --all           Sync all Zeek log types instead of the default subset.
    --dest          SSH destination target (e.g hostname, IP, user@hostname, user@ip)
    --localdir      Location of Zeek logs on local system. (default: searches common locations)
    --remotedir     Location of Zeek logs on remote system. (default: /opt/zeek/remotelogs/<sensorname>/)
    --rsyncparams   Allows specifying parameters for rsync. Enclose in a pair of single quotes.

        Suggestions:
            --bwlimit=NNN   Limit bandwidth used to NNN kilobytes/sec
            -v              Verbose; list out the files being transferred
            -q              Turn off any messages that are not errors
            -n              Dry run, do not actually transfer files
HEREDOC
	exit
}


require_util () {
	#Returns true if all binaries listed as parameters exist somewhere in the path, False if one or more missing.
        while [ -n "$1" ]; do
                if ! type -path "$1" >/dev/null 2>/dev/null ; then
                        echo Missing utility "$1". Please install it. >&2
                        return 1        #False, app is not available.
                fi
                shift
        done
        return 0        #True, app is there.
} #End of requireutil


cleanup_staging () {
	#Clean up staging directory on exit
	if [ -n "$staging_dir" ] && [ -d "$staging_dir" ]; then
		rm -rf "$staging_dir"
	fi
}


#Check that we have basic tools to continue
require_util awk basename cut date dirname egrep find grep hostname ip nice rsync sed ssh sort tr		|| fail "Missing a required utility"

#ionice is not stricly required; if it exists we'll use it to give all other processes on the system first access to the disk, effectively eliminating the chance that we cause dropped packets from disk contention.
if type -path ionice >/dev/null 2>/dev/null ; then
	nice_me=' ionice -c 3 nice -n 19 '
else
	nice_me=' nice -n 19 '
fi

#Default log types to send
log_type_regex='(conn|dns|http|ssl|x509|known_certs|capture_loss|notice|stats)'

#Parse command line flags
while [ -n "$1" ]; do
	if [ "z$1" = "z--all" ]; then
		log_type_regex='.'  #dot matches all log types
	elif [ "z$1" = "z--localdir" -a -e "$2" ]; then
		local_tld="$2"
		shift
	elif [ "z$1" = "z--remotedir" -a -n "$2" ]; then
		remote_top_dir="$2"
		shift
	elif [ "z$1" = "z--dest" -a -n "$2" ]; then
		if echo "$2" | grep -q '@' ; then
			#User has supplied an "@" symbol in target system, do not add $default_user_on_aihunter
			aih_location="${2}"
		else
			#No "@" symbol in target system, force username to $default_user_on_aihunter
			aih_location="${default_user_on_aihunter}@${2}"
		fi
		shift
	elif [ "z$1" = "z--rsyncparams" -a -n "$2" ]; then
		rsyncparams="$2"
		shift
	elif [ "z$1" = "z-h" -o "z$1" = "z--help" ]; then
		usage
	else
		usage
	fi

	shift
done


if [ -z "$rsyncparams" ]; then
	rsyncparams=" -q "
fi

#Where should we send the bro/zeek logs?
if [ -z "$aih_location" ]; then
	if [ -s /etc/rita/agent.yaml ]; then
		aih_location="${default_user_on_aihunter}@`grep '^[^#]*DatabaseLocation' /etc/rita/agent.yaml 2>/dev/null | sed -e 's/^.*DatabaseLocation:*\W*//'`"
	else
		fail "Destination not set on the command line and no /etc/rita/agent.yaml file to autodetect destination."
	fi
fi

#Find a unique name for this bro/zeek node
#Note that the ID cannot contain:   "/, \, ., ", *, <, >, :, |, ?, $,". It also cannot contain a single space or null character.  Avoiding comma too just in case.
#It must also be <=53 characters, as mongo has a maximum database name size of 64 chars and we need to leave space for -YYYY-MM-DD
if [ -s /etc/rita/agent.yaml -a -n "`grep '^[^#]*Name' /etc/rita/agent.yaml 2>/dev/null | sed -e 's/^.*Name:*\W*//'`" ]; then
	#Manually setting the hostname to use in agent.yaml is preferred...
	my_id=`grep '^[^#]*Name' /etc/rita/agent.yaml 2>/dev/null | sed -e 's/^.*Name:*\W*//' | tr -dc 'a-zA-Z0-9_^+=' | cut -c -52`
else
	#...but if no name is forced, we use the short hostname + the primary IP, which should be unique.
	#Following is short form of the hostname, then "__", then the primary IP ipv4 address (one for the default route) of the system.
	#The tr command strips off spaces or odd characters in hostname
	my_id=`hostname -s | tr -dc 'a-zA-Z0-9_^+='`"__"`ip route get 8.8.8.8 | awk '{print $NF;exit}' | tr -dc 'a-zA-Z0-9_^+='`
	my_id=`echo "$my_id" | cut -c -52`
fi

extra_ssh_params=' '
if [ -s "$HOME/.ssh/id_rsa_dataimport" ]; then
	extra_ssh_params=" -i $HOME/.ssh/id_rsa_dataimport "
fi

#Make sure we can ssh to the aihunter system first
if ! can_ssh "$aih_location" "-o" 'PasswordAuthentication=no' $extra_ssh_params ; then
	if [ -s "$HOME/.ssh/id_rsa" -a -s "$HOME/.ssh/id_rsa.pub" ]; then
		status "Transferring the RSA key to $aih_location - please provide the password when prompted"
		cat "$HOME/.ssh/{id_dsa.pub,id_ecdsa.pub,id_rsa.pub,id_rsa_dataimport.pub}" 2>/dev/null \
		 | ssh "$aih_location" 'mkdir -p .ssh ; cat >>.ssh/authorized_keys ; chmod go-rwx ./ .ssh/ .ssh/authorized_keys'
	elif [ -s "$HOME/.ssh/id_rsa" -o -s "$HOME/.ssh/id_rsa.pub" ]; then
		fail "Unable to ssh to $aih_location, and one of the keys exist.  Please transfer the public key to $aih_location, make sure you can ssh from here, and rerun this script"
	elif [ ! type -path ssh-keygen >/dev/null 2>/dev/null ]; then
		fail "Unable to ssh to $aih_location, and we do not have a key generator.  Please create a keypair, transfer the public key to $aih_location, make sure you can ssh from here, and rerun this script"
	else
		#Create ssh key if it doesn't exist, and push to aihunter server or ask user to do so.
		status "Creating a new RSA key with no passphrase"
		ssh-keygen -b 2048 -t rsa -N '' -f "$HOME/.ssh/id_rsa"
		status "Transferring the RSA key to $aih_location - please provide the password when prompted"
		cat "$HOME/.ssh/{id_dsa.pub,id_ecdsa.pub,id_rsa.pub}" 2>/dev/null \
		 | ssh "$aih_location" 'mkdir -p .ssh ; cat >>.ssh/authorized_keys ; chmod go-rwx ./ .ssh/ .ssh/authorized_keys'
	fi

	if ! can_ssh "$aih_location" "-o" 'PasswordAuthentication=no' $extra_ssh_params ; then
		fail "Unable to ssh to $aih_location using something other than a password"
	fi
fi

#What local directory holds the bro/zeek logs?
#Make sure the directory ends in a "/".
if [ -z "$local_tld" ]; then
	# Check for zeek paths first
	if [ -d /storage/zeek/logs/ ]; then				#Custom
		local_tld='/storage/zeek/logs/'
	elif [ -d /opt/zeek/logs/ ]; then				#Zeek as installed by Rita
		local_tld='/opt/zeek/logs/'
	elif [ -d /usr/local/zeek/logs/ ]; then				#Zeek default
		local_tld='/usr/local/zeek/logs/'
	elif [ -d /var/lib/docker/volumes/var_log_zeek/_data/ ]; then	#Blue vector
		local_tld='/var/lib/docker/volumes/var_log_zeek/_data/'
	elif [ -d /nsm/zeek/logs/ ]; then				#Security onion
		local_tld='/nsm/zeek/logs/'
	# Check Bro paths
	elif [ -d /storage/bro/logs/ ]; then				#Custom
		local_tld='/storage/bro/logs/'
	elif [ -d /opt/bro/logs/ ]; then				#Bro as installed by Rita
		local_tld='/opt/bro/logs/'
	elif [ -d /usr/local/bro/logs/ ]; then				#Bro default
		local_tld='/usr/local/bro/logs/'
	elif [ -d /var/lib/docker/volumes/var_log_bro/_data/ ]; then	#Blue vector
		local_tld='/var/lib/docker/volumes/var_log_bro/_data/'
	elif [ -d /nsm/bro/logs/ ]; then				#Security onion
		local_tld='/nsm/bro/logs/'
	else
		fail 'Unable to locate top level directory for bro/zeek logs, please rerun script, specifying the top level path to bro/zeek logs with --localdir .'
	fi
fi

ids_name='zeek'
if [[ $local_tld == *"bro"* ]]; then
	ids_name='bro'
fi

if [ -z "$remote_top_dir" ]; then
	remote_top_dir="/opt/$ids_name/remotelogs/$my_id/"
fi

status "Sending logs to rita/aihunter server $aih_location , My name: $my_id , local dir: $local_tld , remote dir: $remote_top_dir"

status "Preparing remote directories"
ssh $extra_ssh_params "$aih_location" "mkdir -p ${remote_top_dir}"

cd "$local_tld" || fail "Unable to change to $local_tld"

# Find candidates, excluding 'current' directory
send_candidates=`find . -type f -mtime -3 -iname '*.gz' -not -path '*/current/*' | egrep "$log_type_regex" | grep -v '/\.' | sort -u`

if [ -z "$send_candidates" ]; then
	echo
	printf "WARNING: No logs found, if your log directory is not $local_tld please use the flag: --localdir [bro_zeek_log_directory]"
	echo
	exit 0
fi

# Create staging directory for flattened structure
staging_dir="${staging_base_dir}.$$"
mkdir -p "$staging_dir" || fail "Unable to create staging directory $staging_dir"

# Set trap to clean up staging directory on exit
trap cleanup_staging EXIT

status "Preparing files with flattened structure (date prefix)"

# Process each file: create hard link with date prefix
file_count=0
for file in $send_candidates; do
	# file format: ./2026-01-25/conn.00:00:00-00:00:43.log.gz
	# Extract date from path (second component)
	date_part=$(echo "$file" | cut -d'/' -f2)
	
	# Validate date format (YYYY-MM-DD)
	if echo "$date_part" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
		filename=$(basename "$file")
		new_name="${date_part}_${filename}"
		
		# Try hard link first, fall back to copy if cross-filesystem
		if ! ln "${local_tld}/${file#./}" "$staging_dir/$new_name" 2>/dev/null; then
			cp -p "${local_tld}/${file#./}" "$staging_dir/$new_name"
		fi
		file_count=$((file_count + 1))
	else
		# If not in date directory, use file as-is (shouldn't happen in normal operation)
		filename=$(basename "$file")
		if ! ln "${local_tld}/${file#./}" "$staging_dir/$filename" 2>/dev/null; then
			cp -p "${local_tld}/${file#./}" "$staging_dir/$filename"
		fi
		file_count=$((file_count + 1))
	fi
done

status "Prepared $file_count files for transfer"

if [ $file_count -eq 0 ]; then
	status "No files to transfer"
	exit 0
fi

status "Transferring files to $aih_location"

# rsync without -R (no relative paths), transfer staging directory contents
# --ignore-existing: skip files that already exist on destination
flock -xn "$HOME/rsync_log_transport.`echo $aih_location | sed -e 's/@/_/g'`.lck" \
	timeout --kill-after=60 7080 $nice_me rsync $rsyncparams -av \
	-e "ssh $extra_ssh_params" \
	"$staging_dir/" "$aih_location:${remote_top_dir}/" \
	--delay-updates --chmod=Do+rx,Fo+r --ignore-existing

retval=$?
if [ "$retval" == "1" ]; then
	status "Unable to obtain lock and run a new copy of rsync as the previous rsync appears to still be running."
elif [ "$retval" == "124" -o "$retval" == "129" ]; then
	status "Rsync was forcibly terminated as it was running too long."
elif [ "$retval" == "0" ]; then
	status "Rsync finished transferring without error."
fi

# Staging directory cleanup is handled by trap
status "Transfer complete"
