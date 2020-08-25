#!/bin/bash

npy=venv/bin/nitropy

function make_title
{
	echo "########################################################################"
	echo "## $1"
	echo "## $2"
	echo -n ">> press enter to continue... "; read foo
}

function askout
{
	echo -n "<<<<<<<<<<< stop? "
	read inp

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
	make_title 'Testing Nitrokey - FIDO2' \
		'Please insert a Nitrokey FIDO2 (will be wiped!)'

	run ls
	run fido2 list
	run fido2 make-credential

	echo "press again..."
	out=`${npy} fido2 make-credential | tail -n 1`
	echo key $out

	run fido2 challenge-response $out my_challenge

	run fido2 reboot

	echo "sleeping for 10secs..."
	sleep 10

	run fido2 verify
	run fido2 update
	run fido2 verify
	run fido2 reset

}

function teststart
{
	make_title 'Testing Nitrokey - Start' \
		'Please insert a Nitrokey Start (will be wiped!)'

	run ls
	run start list
	run start set-identity 0
	run start set-identity 1
	run start set-identity 2
	run start set-identity 0
	run start update

}

testfido2

teststart




