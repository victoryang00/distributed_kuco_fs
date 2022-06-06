cmd_/root/bento/bentofs/Module.symvers := sed 's/\.ko$$/\.o/' /root/bento/bentofs/modules.order | scripts/mod/modpost -m -a  -o /root/bento/bentofs/Module.symvers -e -i Module.symvers   -T -
