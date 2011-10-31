#!/bin/bash


clear

sudo ant clean 2>&1 > /dev/null

sudo ant compile && \

sudo ant clean; ant dist


