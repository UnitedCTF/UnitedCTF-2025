# V1.0 Commands

## Open Command

Command Id: 0x1

### Description:
Open a file.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | String | Filename | The name of the file to open |
| **2** | Integer | Mode | The mode to open the file in (0 for read, 1 for write, 2 for both) |
| **3** | Register | Result Register | The register to store the file descriptor |

## Create Ptr Command

Command Id: 0x2

### Description:
Create a pointer to a memory location.

**<span style="color: red;">! Careful, this command overwrites the r10 and r11 registers !</span>**

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Integer | Size | Size of memory to allocate (must be between 1 and 4096 bytes) |
| **2** | Register | Result Register | Register to store the pointer |


## Read Command

Command Id: 0x3

### Description:
Read from a file descriptor into a pointer.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Integer | Size | The number of bytes to read |
| **2** | Register | File Descriptor Location | The register containing the file descriptor |
| **3** | Register | Buffer Location | The register containing the pointer to the buffer where the data will be read into |

## Print Command

Command Id: 0x4

### Description:
Print a string to the console.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Integer | Size | Size of the string to print |
| **2** | Register | Buffer Location | Register containing the pointer to the buffer with the string data |
