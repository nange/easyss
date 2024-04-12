#!/bin/bash
tun_device=$1

ip tuntap del mode tun dev "$tun_device"
