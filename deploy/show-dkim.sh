#!/bin/bash
sudo docker exec lookup4me python3 -c 'from tools.feedback_dkim import dkim_dns_value; print(dkim_dns_value())'
