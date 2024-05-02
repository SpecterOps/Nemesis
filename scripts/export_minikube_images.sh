#!/usr/bin/bash

# Exports images from Minikube for later import
#   This is so you don't have to redownload everything if doing a minikube delete

# Get Nemesis online and then run:
eval $(minikube docker-env) # Setup docker to use Minikube's docker env

mkdir nemesis_images
docker images --format '{{.Repository}}:{{.Tag}}' | while read image; do
   output_file="$(echo $image | sed 's/[\/:]/_/g').tar";
   docker save --output "$output_file" "$image";
   echo "Saved $image to $output_file";
done