#!/bin/bash

npy=venv/bin/nitropy

function make_title
{
	if [[ "$2" = "" ]]; then
		echo "------------------------------------------------------------------------"
		echo "-> $1"
	else
		echo "########################################################################"
		echo "########################################################################"
    echo "## $1"
	fi

	if [[ "$2" != "" ]]; then
		echo "## $2"
    [[ "$NO_WAIT" = "" ]] && echo -n ">> press enter to continue... " && read foo
	fi
}

function askout
{
	[[ "$NO_WAIT" = "" ]] && echo -n "<<<<<<<<<<< stop? " && read inp

	if [[ "$inp" = "y" ]]; then
		exit 1;
	fi
}

function run
{
	echo
	echo ">>>>>>>>>>> " $npy "$@"
	$npy "$@"
	askout
}

function testfido2
{
	make_title "Testing Nitrokey - FIDO2" \
		"Please insert a Nitrokey FIDO2 (will be wiped!)"

	make_title "Simple listing of device(s)"
	run ls
	run fido2 list

	make_title "resetting and set pin"
	# hrm ...
	#echo -ne "1234\n1234\n" > set_pin.txt
	#echo -ne "1234\n123456\n123456\n" > change_pin.txt

	run fido2 reset
	run fido2 set-pin
	echo "make sure pin is finally: 123456"
	run fido2 change-pin
	run fido2 verify
	#--pin 123456


	make_title "create a credential + challenge-response using it"

	run fido2 make-credential
	echo "press again..."
	out=`${npy} fido2 make-credential | tail -n 1`
	echo key $out
	run fido2 challenge-response $out my_challenge


	make_title "reboot, version, verify, update, verify, reset, version"

	run fido2 reboot
	echo "sleeping for 5secs..."
	sleep 5

	run fido2 version
	run fido2 verify
	run fido2 update
	run fido2 verify
	run fido2 reset
	run fido2 version


	make_title "rng	subcommand(s)"

	run fido2 rng hexbytes
	run fido2 rng hexbytes --count 12

	echo "SKIP: sudo run fido2 rng feedkernel"
	echo "SKIP: run fido2 rng raw"

	make_title "wink, reboot, wink, reboot, reset, set-pin, change-pin, verify"

	run fido2 wink
	run fido2 reboot
	sleep 5
	run fido2 wink
	run fido2 reboot
	sleep 5


	make_title "finally one more reset and then verify"
	run fido2 reset
	run fido2 verify

	make_title "get .hex firmware, gen sign-key, sign, (skipped: flash bad fw), flash good fw"
	wget "https://github.com/Nitrokey/nitrokey-fido2-firmware/releases/download/2.0.0.nitrokey/nitrokey-fido2-firmware-2.0.0-app-to_sign.hex"
	run fido2 util genkey test_key.pem
	run fido2 util sign test_key.pem nitrokey-fido2-firmware-2.0.0-app-to_sign.hex output.json

	#echo "###>>>> THIS ONE WILL FAIL, EXPECTED FAIL:"
	#run fido2 util program bootloader output.json
	#sleep 1

	wget "https://github.com/Nitrokey/nitrokey-fido2-firmware/releases/download/2.1.0.nitrokey/nitrokey-fido2-firmware-2.1.0.json"

	echo "###>>>> THIS ONE MUST WORK - if not: brick!? :D"
	run fido2 util program bootloader nitrokey-fido2-firmware-2.1.0.json
	sleep 1

	make_title "util program aux enter-bootloader, show version, leave + lists & reboots after each"
	run fido2 util program aux enter-bootloader
	sleep 1
	run fido2 list
	run fido2 util program aux bootloader-version
	run fido2 util program aux reboot
	echo "longer sleep"
	sleep 5
	run fido2 list
  run fido2 util program aux leave-bootloader
	sleep 5
	run fido2 list
	run fido2 reboot
	sleep 1
	run fido2 list


}

function teststart
{
	make_title "Testing Nitrokey - Start" \
		"Please insert a Nitrokey Start (will be wiped!)"


	make_title "Simple listing of devices"

	run ls
	run start list

	make_title "setting identity 0, 1, 2, 0"

	run start set-identity 0
	run start set-identity 1
	run start set-identity 2
	run start set-identity 0


	make_title "updating with latest firmware"

	run start update


	make_title "setting identity 2, 0, 1, 0"

	run start set-identity 2
	run start set-identity 0
	run start set-identity 1
	run start set-identity 0
}

if [[ "$1" = "" ]] || [[ "$1" = "fido2" ]]; then
	testfido2
fi

if [[ "$1" = "" ]] || [[ "$1" = "start" ]]; then
	teststart
fi





