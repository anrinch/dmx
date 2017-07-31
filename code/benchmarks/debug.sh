#!/bin/bash
#set -e
set -x
BASEDIR=$(dirname `readlink -f $0`)

################################################
# CONFIGURE THIS CORRECTLY
HDD=/dev/sda3
SSD=/dev/sda2
MOUNTPOINT=/mnt/scratch
MKMINT=${BASEDIR}/../mkmint/mkmint
################################################
# Leave ths alone
ALGORITHM_HASH=sha256
ALGORITHM_HMAC=sha256
JOURNAL_BLOCKS=16384 # 64 MiB
BLOCK_SIZE=4096
SALT=0011223344556677
SECRET=012345abcd

declare -A mkfs_commands
mkfs_commands["ext4_regular"]="mkfs.ext4 -F -E lazy_itable_init=0"
mkfs_commands["ext4_journal"]="mkfs.ext4 -F -E lazy_itable_init=0"
mkfs_commands["fat32"]="mkfs.vfat -F 32 -I"
mkfs_commands["xfs"]="mkfs.xfs -f"
mkfs_commands["ntfs"]="mkfs.ntfs -F -f"

declare -A mount_commands
mount_commands["ext4_regular"]="-t ext4 -o noatime"
mount_commands["ext4_journal"]="-t ext4 -o noatime,data=journal"
mount_commands["fat32"]="-t vfat -o noatime,uid=`id -u`"
mount_commands["xfs"]="-t xfs -o noatime"
mount_commands["ntfs"]="-t ntfs -o noatime"

declare -A block_devices
block_devices["none_ssd"]=$SSD
block_devices["none_hdd"]=$HDD
block_devices["sector_ssd"]="/dev/mapper/meow"
block_devices["sector_hdd"]="/dev/mapper/meow"
block_devices["full_ssd"]="/dev/mapper/meow"
block_devices["full_hdd"]="/dev/mapper/meow"
block_devices["sector_shdd"]="/dev/mapper/meow"
block_devices["full_shdd"]="/dev/mapper/meow"

declare -A mkmint_devices
mkmint_devices["sector_ssd"]="$SSD $SSD"
mkmint_devices["sector_hdd"]="$HDD $HDD"
mkmint_devices["full_ssd"]="$SSD $SSD"
mkmint_devices["full_hdd"]="$HDD $HDD"
mkmint_devices["sector_shdd"]="$SSD $HDD"
mkmint_devices["full_shdd"]="$SSD $HDD"

declare -A journal_modes
journal_modes["sector_ssd"]="sector"
journal_modes["sector_hdd"]="sector"
journal_modes["full_ssd"]="full"
journal_modes["full_hdd"]="full"
journal_modes["sector_shdd"]="sector"
journal_modes["full_shdd"]=""

declare -A file_systems
file_systems["none_ssd"]="ext4_regular ext4_journal"
file_systems["none_hdd"]=${file_systems["none_ssd"]}
file_systems["sector_ssd"]="ext4_regular"
file_systems["sector_hdd"]="ext4_regular"
file_systems["full_ssd"]="ext4_regular"
file_systems["full_hdd"]="ext4_regular"
file_systems["sector_shdd"]="ext4_regular"
file_systems["full_shdd"]="ext4_regular"

drop_cache() {
    echo "Dropping caches..."
    echo 3 | sudo tee --append /proc/sys/vm/drop_caches > /dev/null
    echo "Sleeping 2 seconds..."
    sleep 2
}

#DD_STREAM_SIZE=256         # 2097152 # 1048576 # 4096 MiB
DD_STREAM_SIZE=262144
# Turn off and on tests here FALSE / TRUE, or comma seperater / empty
DD=TRUE
DATABASE=FALSE
LINUX_UNTAR=FALSE
#FILEBENCHMARKS="filemicro_rread.f filemicro_rwritefsync.f filemicro_seqread.f filemicro_seqwritefsync.f varmail.f"
FILEBENCHMARKS=""
MODES="sector_hdd"

for MODE in $MODES; do
    echo "Running tests for ${MODE}"
    DIRECTORY=${BASEDIR}/results_`date +%Y%m%d-%H%M%S`
    FILE_PREFIX=${MODE}
    BLOCK_DEVICE=${block_devices[${MODE}]}

    if [ ! -d $DIRECTORY ]; then
        mkdir $DIRECTORY
    fi

    if [ ${mkmint_devices[$MODE]+_} ]; then
        echo "Mkmint formatting disk..."
        COMMAND=`eval sudo ${MKMINT} ${mkmint_devices[$MODE]} ${BLOCK_SIZE} ${JOURNAL_BLOCKS} ${ALGORITHM_HASH} ${SALT} ${ALGORITHM_HMAC} ${SECRET} lazy ${journal_modes[$MODE]} | tail -1`
        if [ $? -ne 0 ]; then
            echo "Failed to run mkmint"
            exit 1
        fi
        echo "Mounting deivce mapper..." $COMMAND
        eval "sudo ${COMMAND}"
	eval "sudo dmsetup mknodes"
        if [ $? -ne 0 ]; then
            echo "Failed to run dmsetup create"
            exit 1
        fi
    fi
   
    if [ "$DD" == "TRUE" ]; then 
#        drop_cache
#        echo "Running dd read...${BLOCK_DEVICE}"
#        sudo dd if=${BLOCK_DEVICE} of=/dev/null bs=4k count=${DD_STREAM_SIZE} &>> ${DIRECTORY}/${FILE_PREFIX}_dd_read.txt
        
        drop_cache
        echo "Running dd write...${BLOCK_DEVICE}"
#        sudo dd of=${BLOCK_DEVICE} if=/dev/zero bs=1M count=${DD_STREAM_SIZE} conv=fsync &>> ${DIRECTORY}/${FILE_PREFIX}_dd_write.txt
	sudo dd of=${BLOCK_DEVICE} if=/dev/zero bs=4k count=${DD_STREAM_SIZE} conv=fsync &>> ${DIRECTORY}/${FILE_PREFIX}_dd_write.txt
    fi
    


    mv $DIRECTORY ${DIRECTORY}_done

    sync


    if [ ${mkmint_devices[$MODE]+_} ]; then
        sudo dmsetup suspend meow
        if [ $? -ne 0 ]; then
            echo "Failed to suspend device mapper"
            exit 1;
        fi
    
        sudo dmsetup remove meow
        if [ $? -ne 0 ]; then
            echo "Failed to remove device mapper"
            exit 1;
        fi
    fi
done    
