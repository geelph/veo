//go:build !passive

package cli

import (
	"veo/pkg/logger"
)

const passiveBuild = false

// Execute 执行CLI命令（默认构建：仅主动扫描）
func Execute() {
	args := bootstrapCLI()
	if handlePreScanShortCircuit(args) {
		return
	}

	displayStartupInfo(args)

	if err := runActiveScanMode(args); err != nil {
		logger.Fatalf("主动扫描失败: %v", err)
	}
}
