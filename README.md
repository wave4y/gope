# gope

读取当前进程中**已加载的 PE32+ 模块**，枚举导出、查询名称或序号，并提供 Windows 原生函数调用接口。需要 Go 1.16 或更高版本，无第三方模块依赖。

内存读取和原生调用支持 **Windows/amd64**。其他平台可以编译本包，对应操作返回 `ErrUnsupportedPlatform`。

## 安装

```sh
go get github.com/wave4y/gope
```

```go
import "github.com/wave4y/gope"
```

已有项目更新 import 路径后运行 `go mod tidy`。模块路径与仓库地址统一使用 GitHub。

## 示例：查看已加载模块的导出

下面的示例在 Windows/amd64 运行；它只读取导出信息，不执行枚举出的函数。

```go
package main

import (
    "fmt"
    "log"
    "syscall"

    "github.com/wave4y/gope"
)

func main() {
    dll, err := syscall.LoadDLL("ntdll.dll")
    if err != nil {
        log.Fatal(err)
    }
    defer dll.Release()

    pe, err := gope.OpenPE64(uintptr(dll.Handle))
    if err != nil {
        log.Fatal(err)
    }
    exports, err := pe.Exports()
    if err != nil {
        log.Fatal(err)
    }
    for i, export := range exports {
        if i == 10 {
            break
        }
        fmt.Printf("name=%q ordinal=%d address=%#x forwarder=%q\n",
            export.Name, export.Ordinal, export.Address, export.Forwarder)
    }
}
```

参数是当前进程中已加载映像的基址，**不是磁盘文件路径或 PE 文件字节**。RVA 按加载后的映像布局解释。调用者负责保持模块加载状态；`PE64` 不拥有 DLL 句柄，也不会阻止外部卸载模块。

## 主要接口

| 接口 | 结果 |
| --- | --- |
| `OpenPE64(baseAddr)` | 校验 PE32+ 头和目录，返回 `(*PE64, error)` |
| `(*PE64).Exports()` | 返回 `([]ExportInfo, error)`，包含有名、纯序号和转发导出 |
| `(*PE64).FindProc(name)` | 按名称查找直接导出，返回 `(ExportFunc, error)` |
| `(*PE64).FindOrdinal(ordinal)` | 按包含 Base 偏移的公开序号查找直接导出 |
| `(*ExportFunc).Call(args...)` | 调用原生地址，支持 0～18 个 `uintptr` 参数 |
| `ReadValue(addr)` | 读取指针宽度的值，返回 `(uintptr, error)` |
| `ReadString(addr, maxLength)` | 读取 NUL 结尾字符串，返回 `(string, error)` |

`ExportInfo` 提供 `Name`、`Ordinal`、`RVA`、`Address`、`Forwarder`。纯序号导出的 `Name` 为空；空地址槽会跳过；多个名称指向同一地址的别名会保留。转发导出的 `Address` 为 0，`Forwarder` 保留目标字符串；查询转发导出返回 `ErrForwardedExport`，不会自动加载 DLL 或解析转发链。

导出地址也可能指向数据。`Call` 要求调用者确认有效的可执行地址、Windows amd64 ABI、参数及返回值类型，并保持所属模块和指针参数有效。它不是任意地址的安全执行器。Windows 的非零 LastError 按原样返回，零值归一为 `nil`；是否调用成功仍应依据目标函数约定的返回值判断。

使用 `errors.Is` 可以区分 `ErrInvalidAddress`、`ErrInvalidPE`、`ErrNotFound`、`ErrForwardedExport`、`ErrTooManyArguments`、`ErrInvalidLimit` 和 `ErrUnsupportedPlatform`。公共 PE 头字段是独立快照，修改这些字段不会改变内部解析范围或元数据。

## 边界与兼容性

- 校验 MZ/PE/PE32+ 标识、声明的可选头和目录长度、映像范围、序号索引及字符串终止。不存在导出或导入目录是合法情况。
- 映像最大 2 GiB；函数表和名称表各最多 1,048,576 项；单个导出名称或转发字符串最多 65,535 字节加 NUL，每次 `Exports` 的累计字符串读取上限为 16 MiB。
- `ReadString` 的长度上限为 1～65,536 字节，包含终止符；不可读内存或未终止字符串返回错误，不返回部分文本。
- 原 `NewPE64`、`GetExportFunctions`、`NewProc`、`Value`、`Strptr`、`Hex`、`BeepF` 保留。建议使用带错误返回的新接口。
- `NewPE64` 失败返回 `nil`；`GetExportFunctions` 仅保留有名的直接导出，解析失败返回 `nil`；`NewProc` 查找失败或遇到转发导出返回零值。
- Windows/amd64 下，`Call` 的 nil 接收者或零地址返回 `ErrInvalidAddress`，超过 18 个参数返回 `ErrTooManyArguments`，不再因此 panic。非支持平台的 `Call` 返回 `ErrUnsupportedPlatform`。
- `Value` 读取失败返回 0；`Strptr` 保留 255 字节读取上限，失败或未终止时返回空字符串，不再静默截断。
- `ExportFunc` 仍只有 `Name` 和 `Addr` 两个字段，兼容原有结构体字面量。`BYTE` 更正为 `uint8`，使用负常量的旧代码需要调整；`PVOID` 保留历史 `uint32` 定义并标为弃用，实际原生地址使用 `uintptr`。

内存读取使用当前进程的 `ReadProcessMemory`，将不可读页面报告为错误；解析与调用仍要求映像在使用期间保持有效。

## 结构与验证

```text
types.go / errors.go        PE 结构、导出元数据与错误
pe.go                       PE32+ 校验和导出解析
memory_windows.go           Windows 当前进程内存读取
call_windows.go             Windows amd64 原生调用
platform_other.go           非支持平台实现
helpers.go                  读取辅助及兼容入口
pe_test.go                  构造映像、畸形输入及边界测试
platform_windows_test.go    系统加载器对照、内存读取、0～18 参数调用
platform_other_test.go      非支持平台行为测试
```

```sh
go test ./...
go vet ./...
go test -gcflags=all=-d=checkptr=2 ./...
```

测试包含名称与序号顺序不一致、别名、纯序号、空槽、转发、无目录、溢出、截断、长名称及资源限制。Windows 集成测试与系统加载器核对真实导出，并通过本进程计算回调验证参数转发。

格式与读取语义参考：[Microsoft PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)、[ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)。
