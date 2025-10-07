# V2.0 Commands

## Create Jump Command

Command Id: 0x0

### Description:
Create a jump command with the given id. This command is used to create a jump command that can be used later.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Integer | ID | Unique identifier for the jump command |

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

**<span style="color: red;">! Careful, this command will overwrite the r10 and r11 registers during execution !</span>**

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
| **1** | BigInt | Value | The value to add to the register |
| **2** | Register | Register | The register to add the value to |

## Add True Label Command

Command Id: 0x7

### Description:
Add a label to jump to if a condition is true.

**<span style="color: red;">! Important: You need to have called the CreateJumpCommand before this command. !</span>**

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Integer | ID | The ID of the jump command |

## Add False Label Command

Command Id: 0x8

### Description:
Add a label to jump to if a condition is false.

**<span style="color: red;">! Important: You need to have called the CreateJumpCommand before this command. !</span>**

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Integer | ID | The ID of the jump command |

## Compare Register Command

Command Id: 0x9

### Description:
Jumps to a label depending on the comparison of two registers and a condition.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Integer | ID | The ID of the jump command |
| **2** | Register | Register 1 | First register for comparison |
| **3** | Register | Register 2 | Second register for comparison |
| **4** | JumpCondition | Condition | The condition for the comparison |

## Set Loop Counter Command

Command Id: 0xA

### Description:
Set the loop counter.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Integer | Value | The value to set the loop counter to |

## Set Loop Counter From Register Command

Command Id: 0xAA

### Description:
Set the loop counter.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Register | Value | The register containing the value to set the loop counter to |

## XOR Value Command

Command Id: 0xB

### Description:
XOR a value with a register.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | BigInt | Key | The value to XOR with the register |
| **2** | Register | Register | The register to XOR with |

## XOR From Register Command

Command Id: 0xBB

### Description:
XOR a register with a register.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Register | Key | The register containing the key to XOR with |
| **2** | Register | Register | The register to XOR with |

## Create String Command

Command Id: 0xC

### Description:
Create a string in the data section and loads it into a register.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | String | String | The string to create in the data section |
| **2** | Register | Register | The register to load the string pointer into |
| **3** | Integer | ID | Unique identifier for the string |

## Load From Buffer Command

Command Id: 0xD

### Description:
Load 8 bytes into a register.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Register | Buffer Location | The register containing the buffer pointer |
| **2** | Integer | Offset | The offset in the buffer to read from |
| **3** | Register | Register | The register to load the value into |

## Iterate Loop Command

Command Id: 0xE

### Description:
Iterate the loop with the given id.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Integer | ID | The ID of the loop |

## Loop Start Command

Command Id: 0xF

### Description:
Add a label to loop to.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Integer | ID | Unique identifier for the loop |

## Print Command (WIP)

Command Id: 0x99

### Description:
Print command. Currently prints only using the power of imagination.

### Arguments:
| Argument Index | Type | Name | Description |
|---------|---------|----------|----------|
| **1** | Register | Register | The register you want to eventually print when the function will work, I guess |
