#!/usr/bin/bash

# Exports images from Minikube for later import
#   This is so you don't have to redownload everything if doing a minikube delete

minikube delete && minikube start
eval $(minikube docker-env) # Setup docker to use Minikube's docker env

cd nemesis_images
for image_file in *.tar; do
   docker load --input "$image_file";
   echo "Loaded $image_file";
done