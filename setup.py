from glob import glob

from setuptools import Extension, setup

core = sorted(glob("src/core/*.c"))
ext = Extension(
    "vmem._core",
    sources=["src/bindings/module.c"] + core,
    include_dirs=["include"],
    extra_compile_args=["-O2", "-Wall", "-Wextra", "-std=c11",
                        "-Wno-unused-parameter"],
)

setup(ext_modules=[ext])
