docker stop serene_stonebraker
docker rm serene_stonebraker
rm -rf /var/lib/fluid/init*
rm -rf /var/lib/fluid/work*
rm -rf /var/lib/fluid/cow*
rm -rf /var/lib/fluid/lazycopy*
rm -rf /var/lib/fluid/diff*
umount /var/lib/fluid/sshfs*
rm -rf /var/lib/fluid/sshfs*