const std = @import("std");

pub fn infect(mod: *std.Build.Module) void {
    mod.addCMacro("malloc", "zmalloc");
    mod.addCMacro("malloc_usable_size", "zmalloc_usable_size");
    mod.addCMacro("realloc", "zrealloc");
    mod.addCMacro("calloc", "zcalloc");
    mod.addCMacro("free", "zfree");
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const root_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
    });

    infect(root_module);

    const exe = b.addExecutable(.{
        .name = "qjs_zig",
        .root_module = root_module,
    });

    // Add all QuickJS C files with GNU_SOURCE defined
    exe.addCSourceFiles(.{
        .files = &.{
            "qjs.c",
            // "qjsc.c",
            "quickjs-libc.c",
            "quickjs.c",
            "cutils.c",
            "dtoa.c",
            "libunicode.c",
            "libregexp.c",
        },
        .flags = &.{
            // "-fsanitize=address",
            "-Wall",
            "-Wextra",
            "-D_GNU_SOURCE",
            "-DCONFIG_VERSION=\"2021-03-27\"",
            "-DDUMP_BYTECODE",
            // "-DDUMP_FREE",
            // "-DDUMP_SHAPES",
            // "-DDUMP_MEM",
            // "-DDUMP_OBJECTS",
            // "-DDUMP_GC",
        },
    });

    exe.linkLibC();
    exe.linkSystemLibrary("m"); // Link math library
    exe.linkSystemLibrary("dl"); // Link dynamic loading library
    exe.linkSystemLibrary("pthread"); // Link pthread if needed
    // exe.linkSystemLibrary("asan");

    const cDep = b.addTranslateC(.{ .root_source_file = b.path("./quickjs.h"), .target = target, .optimize = optimize });

    const zigMod =
        b.createModule(.{
            .root_source_file = b.path("lib.zig"),
            .target = target,
            .optimize = optimize,
        });

    zigMod.addImport("quickjs", cDep.createModule());

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "ziglib",
        .root_module = zigMod,
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
    });

    exe.linkLibrary(lib);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
