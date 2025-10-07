# V1.1 Commands

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

## Write Command

Command Id: 0x4

### Description:
Write a string to a file descriptor.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Integer | Size | The number of bytes to write |
| **2** | Register | Buffer Location | The register containing the pointer to the buffer with the data to write |
| **3** | Register | File Descriptor Location | The register containing the file descriptor |

## Set Value Command

Command Id: 0x5

### Description:
Set a value in a register.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Integer | Value | The value to set in the register |
| **2** | Register | Register | The register to store the value |

## Add Value Command

Command Id: 0x6

### Description:
Add a value to a register.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Integer | Value | The value to add to the register |
| **2** | Register | Register | The register to add the value to |

## Create String Command

Command Id: 0xB

### Description:
Create a string in the data section and loads it into a register.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | String | String | The string to create in the data section |
| **2** | Register | Register | The register to load the string pointer into |
| **3** | Integer | ID | Unique identifier for the string |
