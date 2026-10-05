#!/usr/bin/env bash
mkdir -p Prebuilt-Images

for IMAGE in "client" "fw1" "webserver" "fw2" "authserver" "caserver" "logserver"; do
    echo "--- Save $IMAGE image in ${IMAGE}.tar ---"
    docker save $IMAGE > "Prebuilt-Images/${IMAGE}.tar"
done
echo "Saving Prebuilt-Images completed."