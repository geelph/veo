package cli

import (
	"reflect"
	"testing"
)

func TestBuildHostAllowList(t *testing.T) {
	t.Parallel()

	targets := []string{
		"*.baidu.com",
		"https://*.baidu.com/admin",
		"10.0.0.*",
		"https://api.example.com:8443/path?q=1",
	}

	got := buildHostAllowList(targets)
	want := []string{
		"*.baidu.com",
		"10.0.0.*",
		"api.example.com",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildHostAllowList() = %#v, want %#v", got, want)
	}
}

func TestCLIArgsDefaultDropEnabled(t *testing.T) {
	if !((&ScanController{args: &CLIArgs{}}).timeoutDropEnabled()) {
		t.Fatal("default drop should be enabled")
	}
	if (&ScanController{args: &CLIArgs{DropSet: true, Drop: false}}).timeoutDropEnabled() {
		t.Fatal("explicit --drop=false should disable timeout drop")
	}
}

func TestScanControllerRecordsDroppedTargetsDeduped(t *testing.T) {
	sc := &ScanController{}
	sc.recordDroppedTarget("http://b.example")
	sc.recordDroppedTarget("http://a.example")
	sc.recordDroppedTarget("http://b.example")
	sc.recordDroppedTarget(" ")

	got := sc.droppedTargetList()
	want := []string{"http://a.example", "http://b.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("droppedTargetList() = %#v, want %#v", got, want)
	}
}
