#!/bin/bash

cp $1 /etc/pki/ca-trust/source/anchors/
update-ca-trust force-enable
update-ca-trust extract
