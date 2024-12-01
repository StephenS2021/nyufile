#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#pragma pack(push,1) // Ensures no padding on the struct so that the layout is exactly matched
typedef struct BootEntry {
  unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
  unsigned char  BS_OEMName[8];     // OEM Name in ASCII
  unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
  unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
  unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
  unsigned char  BPB_NumFATs;       // Number of FATs
  unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
  unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
  unsigned char  BPB_Media;         // Media type
  unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
  unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
  unsigned short BPB_NumHeads;      // Number of heads in storage device
  unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
  unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
  unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
  unsigned short BPB_ExtFlags;      // A flag for FAT
  unsigned short BPB_FSVer;         // The major and minor version number
  unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
  unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
  unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
  unsigned char  BPB_Reserved[12];  // Reserved
  unsigned char  BS_DrvNum;         // BIOS INT13h drive number
  unsigned char  BS_Reserved1;      // Not used
  unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
  unsigned int   BS_VolID;          // Volume serial number
  unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
  unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct DirEntry {
  unsigned char  DIR_Name[11];      // File name
  unsigned char  DIR_Attr;          // File attributes
  unsigned char  DIR_NTRes;         // Reserved
  unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
  unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
  unsigned short DIR_CrtDate;       // Created day
  unsigned short DIR_LstAccDate;    // Accessed day
  unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
  unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
  unsigned short DIR_WrtDate;       // Written day
  unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
  unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)

int main(int argc, char *argv[]) {
    int opt;
    int i_flag = 0; int r_flag = 0; int l_flag = 0; int R_flag = 0;
    char *sha1 = NULL;
    char *disk_image = NULL;
    // If no disk image is given throw error
    if(argc < 2){
        printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
        return 1;
    }

    disk_image = argv[1]; // Name of file

    while((opt = getopt(argc - 1, argv + 1, "ilr:R:s:")) != -1){
        switch(opt){
            case 'i':
                i_flag = 1;
                break;
            case 'l':
                l_flag = 1;
                break;
            case 'r':
                r_flag = 1;
                break;
            case 'R':
                R_flag = 1;
                break;
            case 's':
                sha1 = optarg;
                break;
            default:
                fprintf(stderr, "Error: please provide required file and flags");
                return 1;

        }
    }

    if (i_flag + l_flag + r_flag + R_flag > 1) {
        fprintf(stderr, "Error: flags are mutually exclusive\n");
        return EXIT_FAILURE;
    }

    if (R_flag && sha1 == NULL) {
        fprintf(stderr, "Error: Option -R requires -s sha1.\n");
        return EXIT_FAILURE;
    }
    int fd = open(disk_image, O_RDWR);
    if(fd == -1){
        printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
        return 1;
    }

    struct stat sb;
    if(fstat(fd, &sb) == -1){
        fprintf(stderr, "Error: unable to access file\n");
        return 1;
    }

    char *disk_map_addr = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0); // address of the mapped fat32 filesystem
    if (disk_map_addr == MAP_FAILED){
        fprintf(stderr, "Error: unable to read file\n");
        close(fd);
        return 1;
    }

    BootEntry *boot = (BootEntry *)(disk_map_addr + 0x0000);

    if (i_flag) {
        printf("Number of FATs = %hu\n", boot->BPB_NumFATs);
        printf("Number of bytes per sector = %hu\n", boot->BPB_BytsPerSec);
        printf("Number of sectors per cluster = %hu\n", boot->BPB_SecPerClus);
        printf("Number of reserved sectors = %d\n", boot->BPB_RsvdSecCnt);
    } else if (l_flag) {
        // locating contents of the root directory
        unsigned int root_sector = boot->BPB_RsvdSecCnt + (boot->BPB_NumFATs * boot->BPB_FATSz32) + (boot->BPB_RootClus - 2) * boot->BPB_SecPerClus; // Calculate root directory (sector) by (reserved sector count + sectors of the total fats + sector number - 2 (accounting for first 2 reserved sectors included in BPB_RsvdSecCnt))
        unsigned int root_addr = root_sector * boot->BPB_BytsPerSec; // get the location of the root sector in bytes
        unsigned int dir_entry_size = 32; // size of each directory entry in the root directory
        unsigned int cluster_size = boot->BPB_BytsPerSec * boot->BPB_SecPerClus; // size of one cluster in bytes

        unsigned int total_entries_per_cluster = cluster_size / dir_entry_size; // calculate the number of total entries in each cluster
        
        unsigned int fat_start = boot->BPB_RsvdSecCnt * boot->BPB_BytsPerSec; // Start of FAT in bytes

        int directory_count = 0;
        unsigned int cluster = boot->BPB_RootClus; // current cluster starting from root (2)
        unsigned int cluster_addr;

        while (cluster < 0xFFFFFF8) {
            cluster_addr = (root_addr + (cluster - 2) * cluster_size); // Address of the current cluster

            for( int i = 0; i < (int) total_entries_per_cluster; i++){
                // find from memory the current dir entry as => start address of the fat32 filesys + the address of the current cluster + (i (the current sector of the cluster) * the size of an entry in root_dir)
                DirEntry *entry = (DirEntry *)(disk_map_addr + cluster_addr + (i * dir_entry_size)); 

                // stop if we hit an empty entry
                if (entry->DIR_Name[0] == 0x00) break;
                // skip any deleted entries
                if (entry->DIR_Name[0] == 0xE5) continue;

                unsigned char format_dir_name[11];


                // read the name for directory / file
                int k,j = 0;
                for(k = 0; k < 8; k++){
                    if(entry->DIR_Name[k] != ' '){
                        format_dir_name[j++] = entry->DIR_Name[k];
                    }
                }
                // If given a file extension
                if(entry->DIR_Name[8] != ' '){
                    format_dir_name[j++] = '.';
                    for(k = 8; k < 11; k++){
                        if(entry->DIR_Name[k] != ' '){
                            format_dir_name[j++] = entry->DIR_Name[k];
                        }
                    }
                }
                format_dir_name[j] = '\0'; // Add null terminator

                unsigned int file_starting_cluster = entry->DIR_FstClusHI << 16 | entry->DIR_FstClusLO; // find location of first cluster of file contents


                if(entry->DIR_Attr == 0x10){ // if folder / directory
                    printf("%s/ (starting cluster = %d)\n", format_dir_name, file_starting_cluster);
                }else if(file_starting_cluster == 0x0){
                    printf("%s (size = %d)\n", format_dir_name, entry->DIR_FileSize);
                }else{
                    printf("%s (size = %d, starting cluster = %d)\n", format_dir_name, entry->DIR_FileSize, file_starting_cluster);
                }
                directory_count++;
            }

            cluster = *(unsigned int *)(disk_map_addr + fat_start + (cluster*4)); // Get next cluster as the start of the mapped file sys + the start addr of the fat + the size of the cluster addr in bytes
        }
        printf("Total number of entries = %d\n", directory_count);

    } else if (r_flag) {
        printf("TODO Recover contiguous file '%s' from disk image: %s\n", disk_image, disk_image);
        if( sha1 != NULL){
            printf("Recover with %s\n", sha1);
        }
    } else if (R_flag) {
        printf("TODO Recover non-contiguous file '%s' with sha1 '%s' from disk image: %s\n", disk_image, sha1, disk_image);
    } else {
        fprintf(stderr, "Usage: %s disk <options>\n", argv[0]);
        return 1;
    }

    
    return 0;
}
