//go:build darwin && cgo && !headless

package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>
#include <stdlib.h>

// menuFont 与 AppKit 给菜单项标题用的字体一致（.AppleSystemUIFont，随系统字号）。
static NSFont *menuFont(void) {
    return [NSFont menuFontOfSize:0];
}

// textWidth 用菜单字体排版一段文本，返回宽度（pt）。
// 只读字体度量，不触碰任何 UI 对象，因此在非主线程调用也是安全的。
double textWidth(const char *s) {
    @autoreleasepool {
        NSString *t = [NSString stringWithUTF8String:s];
        if (t == nil) { return 0; }
        return [t sizeWithAttributes:@{NSFontAttributeName: menuFont()}].width;
    }
}
*/
import "C"

import "unsafe"

// measureTextWidth 返回文本在托盘菜单字体下的排版宽度（单位 pt）。
//
// 用真实字体度量而不是"字符数 * 平均宽度"：菜单字体是比例字体（不同字形宽度可差
// 3 倍），只有真实度量才能让"指标列"在所有服务器地址上落在同一列。
// 它只在后台 goroutine（statsRefresher）里被调用，AppKit 的字体度量是线程安全的，
// 且不涉及任何需要在主线程执行的 UI 操作。
func measureTextWidth(s string) float64 {
	cstr := C.CString(s)
	defer C.free(unsafe.Pointer(cstr))
	return float64(C.textWidth(cstr))
}
