cmd_/root/bento/bentofs/modules.order := {   echo /root/bento/bentofs/bentofs.ko; :; } | awk '!x[$$0]++' - > /root/bento/bentofs/modules.order
