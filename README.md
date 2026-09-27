# gope

用于访问当前进程内已加载 PE64 模块的 Go 库，提供 PE 头结构、导出函数枚举、按名称查找及调用导出函数等接口。

## 安装

```sh
go get github.com/wave4y/gope
```

```go
import "github.com/wave4y/gope"
```

需要 Go 1.16 或更高版本，没有第三方模块依赖。当前实现面向 Windows 64 位环境。

## 接口

- `NewPE64(baseAddr)`：通过当前进程中有效的已加载模块基址访问 PE64 结构；参数不是磁盘文件路径或文件字节。
- `(*PE64).GetExportFunctions()`：枚举导出函数。
- `(*PE64).NewProc(name)`：按名称查找导出函数。
- `(*ExportFunc).Call(args...)`：调用导出函数，支持最多 18 个参数。

已有项目迁移时，将模块和子包导入前缀更新为 `github.com/wave4y/gope`，然后运行 `go mod tidy`。

## 验证

在 Windows amd64 环境运行：

```sh
go test ./...
```

仓库目前没有自动化测试用例；该命令用于检查包能否编译。
