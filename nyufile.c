#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>

// DISK4
// 6400 - FAT
// 6800 - DIR
// 7800 - NOTHING.TXT


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
    char *filename = NULL;
    char *disk_image = NULL;
    // If no disk image is given throw error
    if(argc < 2){
        printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
        return EXIT_SUCCESS;
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
                filename = optarg;
                break;
            case 'R':
                R_flag = 1;
                filename = optarg;
                break;
            case 's':
                sha1 = optarg;
                break;
            default:
                printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
                return EXIT_FAILURE;

        }
    }

    if (i_flag + l_flag + r_flag + R_flag > 1) {
        printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
        return EXIT_FAILURE;
    }

    int fd = open(disk_image, O_RDWR);
    if(fd == -1){
        printf("Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
        return EXIT_FAILURE;
    }

    struct stat sb;
    if(fstat(fd, &sb) == -1){
        fprintf(stderr, "Error: unable to access file\n");
        return EXIT_FAILURE;
    }

    char *disk_map_addr = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0); // address of the mapped fat32 filesystem
    if (disk_map_addr == MAP_FAILED){
        fprintf(stderr, "Error: unable to read file\n");
        close(fd);
        return EXIT_FAILURE;
    }

    BootEntry *boot = (BootEntry *)(disk_map_addr + 0x0000);

    if (i_flag) {
        printf("Number of FATs = %hu\n", boot->BPB_NumFATs);
        printf("Number of bytes per sector = %hu\n", boot->BPB_BytsPerSec);
        printf("Number of sectors per cluster = %hu\n", boot->BPB_SecPerClus);
        printf("Number of reserved sectors = %d\n", boot->BPB_RsvdSecCnt);
        if(munmap(disk_map_addr, sb.st_size) == -1){
            fprintf(stderr, "Error: unable to unmap file");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    } else if (l_flag) {
        // locating contents of the root directory
        unsigned int data_start_sector = boot->BPB_RsvdSecCnt + (boot->BPB_NumFATs * boot->BPB_FATSz32);

        unsigned int dir_entry_size = 32; // size of each directory entry in the root directory (two lines in xxd dump)
        unsigned int cluster_size = boot->BPB_BytsPerSec * boot->BPB_SecPerClus; // size of one cluster in bytes

        unsigned int total_entries_per_cluster = cluster_size / dir_entry_size; // calculate the number of total entries in each cluster

        unsigned int fat_start = boot->BPB_RsvdSecCnt * boot->BPB_BytsPerSec; // Start of FAT in bytes

        int directory_count = 0;
        unsigned int cluster = boot->BPB_RootClus; // current cluster starting from root (2)
        unsigned int cluster_addr;

        while (cluster < 0xFFFFFF8) {
            cluster_addr = (data_start_sector * boot->BPB_BytsPerSec) + ((cluster - 2) * cluster_size);// Address of the current 
            if ((uintptr_t)(disk_map_addr + cluster_addr) >= (uintptr_t)(disk_map_addr + sb.st_size)) {
                fprintf(stderr, "Error: Cluster address out of bounds.\n");
                return EXIT_FAILURE;
            }
            
            for( int i = 0; i < (int) total_entries_per_cluster; i++){
                // find from memory the current dir entry as => start address of the fat32 filesys + the address of the current cluster + (i (the current sector of the cluster) * the size of an entry in root_dir)
                void *entry_addr = disk_map_addr + cluster_addr + (i * dir_entry_size);

                // Validate entry address
                if((uintptr_t)(entry_addr) >= (uintptr_t)(disk_map_addr + sb.st_size)) {
                    fprintf(stderr, "Error: Directory entry address out of bounds.\n");
                    return EXIT_FAILURE;
                }

                DirEntry *entry = (DirEntry *)entry_addr;
                
                // stop if we hit an empty entry
                if (entry->DIR_Name[0] == 0x00 || entry->DIR_Name[0] == '.' || entry->DIR_Name[0] == '\n') break;
                // skip any deleted entries
                if (entry->DIR_Name[0] == 0xE5) continue;

                unsigned char format_dir_name[13];

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
                }else if(file_starting_cluster == 0x0){ // if file is empty?
                    printf("%s (size = %d)\n", format_dir_name, 0);
                }else{
                    printf("%s (size = %d, starting cluster = %d)\n", format_dir_name, entry->DIR_FileSize, file_starting_cluster);
                }
                directory_count++;
            }
            unsigned int *next_cluster = (unsigned int *)(disk_map_addr + fat_start + (cluster * 4));
            
            if ((uintptr_t)(next_cluster) >= (uintptr_t)(disk_map_addr + sb.st_size)) {
                fprintf(stderr, "Error: FAT entry address out of bounds.\n");
                break;
            }

            cluster = *next_cluster; // Get next cluster as the start of the mapped file sys + the start addr of the fat + the size of the cluster addr in bytes

        }
        printf("Total number of entries = %d\n", directory_count);

        if (munmap(disk_map_addr, sb.st_size) == -1) {
            perror("Error unmapping memory");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;

    } else if (r_flag) {
        if( sha1 != NULL){
            printf("Recover with %s\n", sha1);
        }

        unsigned int root_sector = boot->BPB_RsvdSecCnt + (boot->BPB_NumFATs * boot->BPB_FATSz32) + (boot->BPB_RootClus - 2) * boot->BPB_SecPerClus; // Calculate root directory (sector) by (reserved sector count + sectors of the total fats + sector number - 2 (accounting for first 2 reserved sectors included in BPB_RsvdSecCnt))
        unsigned int root_addr = root_sector * boot->BPB_BytsPerSec; // get the location of the root sector in bytes
        unsigned int dir_entry_size = 32; // size of each directory entry in the root directory (two lines in xxd dump)
        unsigned int cluster_size = boot->BPB_BytsPerSec * boot->BPB_SecPerClus; // size of one cluster in bytes

        unsigned int total_entries_per_cluster = cluster_size / dir_entry_size; // calculate the number of total entries in each cluster

        unsigned int fat_start = boot->BPB_RsvdSecCnt * boot->BPB_BytsPerSec; // Start of FAT in bytes

        unsigned int cluster = boot->BPB_RootClus; // current cluster starting from root (2)
        unsigned int cluster_addr;
        int numEntriesFound = 0;
        DirEntry *recoverEntry;

        while (cluster < 0xFFFFFF8) {
            cluster_addr = (root_addr + (cluster - 2) * cluster_size); // Address of the current cluster
            for( int i = 0; i < (int) total_entries_per_cluster; i++){
                // find from memory the current dir entry as => start address of the fat32 filesys + the address of the current cluster + (i (the current sector of the cluster) * the size of an entry in root_dir)
                DirEntry *entry = (DirEntry *)(disk_map_addr + cluster_addr + (i * dir_entry_size)); 

                // stop if we hit an empty entry
                if (entry->DIR_Name[0] == 0x00) break;
                // skip any deleted entries
                if (entry->DIR_Name[0] == 0xE5) {
                    unsigned char format_dir_name[13];

                    // read the name for directory / file
                    int k,j = 0;
                    format_dir_name[j++] = filename[0]; // replace first letter of file
                    for(k = 1; k < 8; k++){
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

                    // compare the reconstructed file name to the input file name
                    if(strcmp(filename, (char *) format_dir_name) == 0){
                        recoverEntry = (DirEntry *)(disk_map_addr + cluster_addr + (i * dir_entry_size)); 
                        numEntriesFound++;
                    }
                }

            }
            // get the next cluster from the fat
            cluster = *(unsigned int *)(disk_map_addr + fat_start + (cluster*4)); // Get next cluster as the start of the mapped file sys + the start addr of the fat + the size of the cluster addr in bytes
        }
        if(numEntriesFound > 1){
            printf("%s: multiple candidates found\n", filename);
            if(munmap(disk_map_addr, sb.st_size) == -1){
                fprintf(stderr, "Error: unable to unmap file");
                return EXIT_FAILURE;
            }
            return EXIT_FAILURE;
        }  
        if(numEntriesFound == 1 && recoverEntry){
            recoverEntry->DIR_Name[0] = filename[0];
            unsigned int file_starting_cluster = recoverEntry->DIR_FstClusHI << 16 | recoverEntry->DIR_FstClusLO; // find location of first cluster of file contents
            
            // Find FAT entry in the disk (logically)
            // unsigned int file_fat_entry = fat_start + (file_starting_cluster*4);

            // Find the actual memory location of that entry
            // unsigned int *mem_fat_entry_WRONG = (unsigned int *) disk_map_addr + file_fat_entry;

            // If the file is not empty, create an entry in the FAT for it
            if(file_starting_cluster != 0x00){
                // If file size is greater than one cluster in bytes
                if((recoverEntry->DIR_FileSize - 1) > cluster_size){
                    unsigned int total_clusters = (recoverEntry->DIR_FileSize + cluster_size - 1) / cluster_size; // calculate the total clusters the file occupies (rounded)
                    
                    unsigned int current_cluster = file_starting_cluster;
                    unsigned int next_cluster;
                    for(unsigned int i = 0; i < total_clusters-1; i++){
                        next_cluster = current_cluster + 1; // get next cluster number

                        unsigned int *mem_fat_entry = (unsigned int *)(disk_map_addr + fat_start + (current_cluster * 4)); // calculate current memory entry
                        *mem_fat_entry = next_cluster; // set fat entry to next cluster

                        current_cluster = next_cluster; // iterate to next cluster
                    }
                    // Set the last entry to EOF
                    unsigned int *last_fat_entry = (unsigned int *)(disk_map_addr + fat_start + (current_cluster * 4));
                    *last_fat_entry = 0x0FFFFFF8;
                } else {
                    // If file is less than or equal to a cluster just set FAT entry to EOF
                    unsigned int *single_cluster_entry = (unsigned int *)(disk_map_addr + fat_start + (file_starting_cluster * 4));
                    *single_cluster_entry = 0x0FFFFFF8;
                }
            }
            printf("%s: successfully recovered\n", filename);
            if(munmap(disk_map_addr, sb.st_size) == -1){
                fprintf(stderr, "Error: unable to unmap file");
                return EXIT_FAILURE;
            }
            return EXIT_SUCCESS;
        }
        printf("%s: file not found\n", filename);
        return EXIT_FAILURE;
    } else if (R_flag) {
        printf("TODO Recover non-contiguous file '%s' with sha1 '%s' from disk image: %s\n", filename, sha1, disk_image);
        if( sha1 != NULL){
            printf("Recover with %s\n", sha1);
        }
    } else {
        fprintf(stderr, "Usage: %s disk <options>\n", argv[0]);
        if(munmap(disk_map_addr, sb.st_size) == -1){
            fprintf(stderr, "Error: unable to unmap file");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
    if(munmap(disk_map_addr, sb.st_size) == -1){
        fprintf(stderr, "Error: unable to unmap file");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}
