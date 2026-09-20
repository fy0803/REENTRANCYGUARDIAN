#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SlitherLoader - Slither 集成和Solidity项目加载

负责：
1. 初始化 Slither 分析器
2. 加载和编译 Solidity 项目
3. 处理编译错误和警告
"""

import re
import shutil
import sys
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path
from slither import Slither
from slither.core.declarations import Contract, FunctionContract
from packaging.version import Version
from solc_select.solc_select import artifact_path, current_version, installed_versions


class SlitherLoader:
    """Slither 加载器"""
    
    def __init__(self, solc_version: Optional[str] = None):
        """
        初始化Slither加载器
        
        Args:
            solc_version: 指定的solc编译器版本
        """
        self.solc_version = solc_version
        self.slither = None
        self._compat_suffix = ".__slither_compat.sol"

    def _artifact_roots(self) -> List[Path]:
        roots: List[Path] = []
        candidates = [
            Path(sys.executable).resolve().parents[1] / ".solc-select" / "artifacts",
            Path.home() / ".solc-select" / "artifacts",
        ]

        for root in candidates:
            if root not in roots:
                roots.append(root)
        return roots

    def _find_solc_binary(self, version: str) -> Optional[str]:
        binary_names = [f"solc-{version}", f"solc-{version}.exe", "solc.exe"]

        for root in self._artifact_roots():
            artifact_dir = root / f"solc-{version}"
            for binary_name in binary_names:
                candidate = artifact_dir / binary_name
                if candidate.exists():
                    return candidate.as_posix()

        try:
            fallback = artifact_path(version)
            if fallback.exists():
                return fallback.as_posix()
        except Exception:
            pass

        return None

    def _solc_select_wrapper(self) -> str:
        venv_wrapper = Path(sys.executable).resolve().parent / "solc.exe"
        if venv_wrapper.exists():
            return str(venv_wrapper)
        return "solc"

    def _solc_select_wrapper_for_version(self, version: str) -> str:
        wrappers = [
            (
                Path(sys.executable).resolve().parents[1] / ".solc-select" / "artifacts",
                Path(sys.executable).resolve().parent / "solc.exe",
            ),
            (Path.home() / ".solc-select" / "artifacts", Path(shutil.which("solc") or "solc")),
        ]
        for artifact_root, wrapper in wrappers:
            if (artifact_root / f"solc-{version}").exists() and wrapper.exists():
                return str(wrapper)
        return self._solc_select_wrapper()

    def _dataset_contracts_root(self, project_path: str) -> Optional[Path]:
        path = Path(project_path).resolve()
        for parent in [path.parent, *path.parents]:
            if parent.name == "contracts" and parent.parent.name == "DAppSCAN-source":
                return parent
        return None

    def _dappscan_dependency_remaps(self, project_path: str, version: Optional[str]) -> List[str]:
        contracts_root = self._dataset_contracts_root(project_path)
        if not contracts_root:
            return []

        oz3 = contracts_root / "Chainsulting-MakiSwap" / "openzeppelin-contracts-3.2.0"
        oz4 = contracts_root / "Chainsulting-SWAPP Protocol-project2" / "openzeppelin-contracts-4.2.0"
        oz_upgradeable = (
            contracts_root
            / "Cystack-AOC ERC-20 V2 - v1.2"
            / "AOC_ERC200x41cc978FaE6f34B25553A498D1e245FDF944FF3E"
            / "@openzeppelin"
            / "contracts-upgradeable"
        )
        hardhat_vendor = Path(__file__).resolve().parents[1] / "vendor"

        if version:
            try:
                use_oz4 = Version(version) >= Version("0.8.0")
            except Exception:
                use_oz4 = False
        else:
            use_oz4 = False

        base_oz = oz4 if use_oz4 and oz4.exists() else oz3
        remaps: List[str] = []

        if oz_upgradeable.exists():
            remaps.append(f"@openzeppelin/contracts-upgradeable/={oz_upgradeable.as_posix()}/")
        if oz3.exists() and not use_oz4:
            remaps.extend(
                [
                    f"@openzeppelin/contracts/math/={(oz3 / 'contracts' / 'math').as_posix()}/",
                    f"@openzeppelin/contracts/token/ERC20/={(oz3 / 'contracts' / 'token' / 'ERC20').as_posix()}/",
                    f"openzeppelin-solidity/contracts/={(oz3 / 'contracts').as_posix()}/",
                ]
            )
        if oz4.exists():
            remaps.extend(
                [
                    f"@openzeppelin/contracts/utils/math/={(oz4 / 'contracts' / 'utils' / 'math').as_posix()}/",
                    f"@openzeppelin/contracts/security/={(oz4 / 'contracts' / 'security').as_posix()}/",
                    f"@openzeppelin/contracts/token/ERC20/utils/={(oz4 / 'contracts' / 'token' / 'ERC20' / 'utils').as_posix()}/",
                    f"@openzeppelin/contracts/token/ERC20/extensions/={(oz4 / 'contracts' / 'token' / 'ERC20' / 'extensions').as_posix()}/",
                    f"@openzeppelin/contracts/token/ERC721/extensions/={(oz4 / 'contracts' / 'token' / 'ERC721' / 'extensions').as_posix()}/",
                    f"@openzeppelin/contracts/token/ERC1155/presets/={(oz4 / 'contracts' / 'token' / 'ERC1155' / 'presets').as_posix()}/",
                    f"@openzeppelin/contracts/token/ERC20/presets/={(oz4 / 'contracts' / 'token' / 'ERC20' / 'presets').as_posix()}/",
                ]
            )
        if base_oz.exists():
            remaps.append(f"@openzeppelin/={base_oz.as_posix()}/")
        if hardhat_vendor.exists():
            remaps.append(f"hardhat/={hardhat_vendor.as_posix()}/hardhat/")

        return remaps

    def _installed_solc_versions(self) -> List[str]:
        discovered: set[str] = set()

        try:
            discovered.update(installed_versions())
        except Exception:
            pass

        pattern = re.compile(r"^solc-(\d+\.\d+\.\d+)$")
        for root in self._artifact_roots():
            if not root.exists():
                continue
            for artifact_dir in root.iterdir():
                if not artifact_dir.is_dir():
                    continue
                match = pattern.match(artifact_dir.name)
                if not match:
                    continue
                version = match.group(1)
                if self._find_solc_binary(version):
                    discovered.add(version)

        return sorted(discovered, key=Version)

    def _extract_pragma(self, project_path: str) -> Optional[str]:
        path = Path(project_path)
        if not path.is_file():
            return None
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None
        match = re.search(r"^[ \t]*pragma\s+solidity\s*([^;]+);", content, flags=re.MULTILINE)
        return match.group(1).strip() if match else None

    def _looks_like_legacy_pre_0_5(self, project_path: str) -> bool:
        path = Path(project_path)
        if not path.is_file():
            return False
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return False
        return bool(
            re.search(r"\bfunction\b[^{;]*\bconstant\b", content)
            or re.search(r"\bthrow\s*;", content)
        )

    def _version_matches_pragma(self, version: str, pragma: str) -> bool:
        current = Version(version)
        pragma = pragma.strip()

        if pragma.startswith("^"):
            base = Version(pragma[1:].strip())
            upper = Version(f"{base.major}.{base.minor + 1}.0") if base.major == 0 else Version(f"{base.major + 1}.0.0")
            return base <= current < upper

        constraints = re.findall(r"(>=|<=|>|<|=)?\s*(\d+\.\d+\.\d+)", pragma)
        if constraints:
            return all(self._compare_version(current, operator or "=", Version(target)) for operator, target in constraints)

        return False

    def _compare_version(self, current: Version, operator: str, target: Version) -> bool:
        if operator == "=":
            return current == target
        if operator == ">=":
            return current >= target
        if operator == "<=":
            return current <= target
        if operator == ">":
            return current > target
        if operator == "<":
            return current < target
        return False

    def _collect_solc_candidates(self, project_path: str) -> List[str]:
        if self.solc_version:
            return [self.solc_version]

        pragma = self._extract_pragma(project_path)
        available = self._installed_solc_versions()
        candidates: List[str] = []

        if pragma:
            matches = [version for version in available if self._version_matches_pragma(version, pragma)]
            if matches:
                candidates.extend(reversed(matches))
            elif re.fullmatch(r"\d+\.\d+\.\d+", pragma):
                requested = Version(pragma)
                same_minor = [
                    version
                    for version in available
                    if Version(version).major == requested.major and Version(version).minor == requested.minor
                ]
                candidates.extend(reversed(same_minor))
        elif self._looks_like_legacy_pre_0_5(project_path):
            legacy_matches = [version for version in available if Version(version) < Version("0.5.0")]
            candidates.extend(reversed(legacy_matches))

        try:
            version, _ = current_version()
            if version not in candidates:
                candidates.append(version)
        except Exception:
            pass

        return candidates

    def _resolve_solc_version(self, project_path: str) -> Optional[str]:
        candidates = self._collect_solc_candidates(project_path)
        return candidates[0] if candidates else None

    def _resolve_solc_binary(self, project_path: str) -> Optional[str]:
        try:
            version = self._resolve_solc_version(project_path)
            if not version:
                return None
            return self._find_solc_binary(version)
        except Exception:
            return None

    def _load_with_slither(self, project_path: str) -> Any:
        last_exc: Optional[Exception] = None
        first_exc: Optional[Exception] = None
        candidates = self._collect_solc_candidates(project_path)
        if not candidates:
            candidates = [None]

        for version in candidates:
            slither_kwargs = {}
            if version:
                binary = self._find_solc_binary(version)
                if not binary:
                    last_exc = FileNotFoundError(f"Unable to locate solc binary for version {version}")
                    continue
                slither_kwargs["solc"] = self._solc_select_wrapper_for_version(version)
                slither_kwargs["solc_solcs_select"] = version
                remaps = self._dappscan_dependency_remaps(project_path, version)
                if remaps:
                    slither_kwargs["solc_remaps"] = remaps
            try:
                return Slither(project_path, **slither_kwargs)
            except Exception as exc:
                if "Stack too deep" in str(exc) and "solc_args" not in slither_kwargs:
                    try:
                        via_ir_kwargs = dict(slither_kwargs)
                        via_ir_kwargs["solc_args"] = "--via-ir --optimize"
                        return Slither(project_path, **via_ir_kwargs)
                    except Exception as via_ir_exc:
                        last_exc = via_ir_exc
                        continue
                if first_exc is None:
                    first_exc = exc
                last_exc = exc

        if first_exc is not None:
            raise first_exc
        if last_exc is not None:
            raise last_exc
        return Slither(project_path)

    def _normalize_spdx_identifiers(self, content: str) -> str:
        lines: List[str] = []
        seen_valid_identifier = False
        for line in content.splitlines(keepends=True):
            if "SPDX-License-Identifier:" not in line:
                lines.append(line)
                continue

            prefix, marker, suffix = line.partition("SPDX-License-Identifier:")
            identifier = suffix.strip()
            if identifier and re.fullmatch(r"[A-Za-z0-9.\-+() ]+", identifier):
                if seen_valid_identifier:
                    newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
                    lines.append(f"{prefix}SPDX-License-Identifier-Removed: {identifier}{newline}")
                else:
                    lines.append(line)
                    seen_valid_identifier = True
                continue

            newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            lines.append(f"{prefix}{marker} UNLICENSED{newline}")

        return "".join(lines)

    def _relax_exact_pragma(self, content: str) -> str:
        available = self._installed_solc_versions()

        def replace(match: re.Match[str]) -> str:
            requested = Version(match.group(1))
            if match.group(1) in available:
                return match.group(0)

            same_minor = [
                version
                for version in available
                if Version(version).major == requested.major and Version(version).minor == requested.minor
            ]
            if not same_minor:
                return match.group(0)

            upper = Version(f"{requested.major}.{requested.minor + 1}.0") if requested.major == 0 else Version(
                f"{requested.major + 1}.0.0"
            )
            return f"pragma solidity >={requested} <{upper};"

        return re.sub(
            r"^[ \t]*pragma\s+solidity\s*=?\s*(\d+\.\d+\.\d+)\s*;",
            replace,
            content,
            flags=re.MULTILINE,
        )

    def _rewrite_compat_content(self, content: str) -> str:
        rewritten = self._strip_trailing_standard_json(content)
        rewritten = self._relax_exact_pragma(rewritten)
        rewritten = self._normalize_spdx_identifiers(rewritten)
        rewritten = self._strip_imports_from_embedded_bundle(rewritten)
        rewritten = self._rewrite_removed_constructor_visibility(rewritten)
        rewritten = self._rewrite_legacy_invalid_jump_label(rewritten)
        rewritten = self._rewrite_legacy_low_level_calls(rewritten)
        return rewritten

    def _strip_trailing_standard_json(self, content: str) -> str:
        marker = re.search(
            r"\n\s*\{\s*\r?\n\s*\"(?:remappings|language|sources|settings)\"\s*:",
            content,
        )
        if not marker:
            return content
        return content[: marker.start()].rstrip() + "\n"

    def _rewrite_removed_constructor_visibility(self, content: str) -> str:
        pragma_match = re.search(r"^[ \t]*pragma\s+solidity\s*([^;]+);", content, flags=re.MULTILINE)
        if not pragma_match:
            return content

        versions = [Version(value) for value in re.findall(r"\d+\.\d+\.\d+", pragma_match.group(1))]
        if versions and min(versions) < Version("0.7.0"):
            return content

        return re.sub(
            r"\bconstructor\s*\((?P<params>[^)]*)\)\s+(?:public|internal)(?P<payable>\s+payable)?",
            lambda match: f"constructor({match.group('params')}){match.group('payable') or ''}",
            content,
        )

    def _strip_imports_from_embedded_bundle(self, content: str) -> str:
        if content.count("SPDX-License-Identifier") < 2 and content.count("SPDX-License-Identifier-Removed") < 1:
            return content

        return re.sub(
            r"^[ \t]*import\s+[^;]+;\s*(?://[^\r\n]*)?\r?\n",
            "",
            content,
            flags=re.MULTILINE,
        )

    def _rewrite_legacy_invalid_jump_label(self, content: str) -> str:
        pattern = re.compile(
            r"(?P<indent>[ \t]*)assembly\s*\{\s*\n"
            r"(?P<body_indent>[ \t]*)(?P<assign>(?P<addr>\w+)\s*:=\s*create\([^\n]*\))\s*\n"
            r"[ \t]*jumpi\(invalidJumpLabel,\s*iszero\(extcodesize\((?P=addr)\)\)\)\s*\n"
            r"(?P=indent)\}",
            re.MULTILINE,
        )

        def replace(match: re.Match[str]) -> str:
            indent = match.group("indent")
            body_indent = match.group("body_indent")
            assign = match.group("assign").strip()
            addr = match.group("addr")
            return (
                f"{indent}assembly {{\n"
                f"{body_indent}{assign}\n"
                f"{indent}}}\n"
                f"{indent}if ({addr} == 0) {{\n"
                f"{indent}  throw;\n"
                f"{indent}}}"
            )

        return pattern.sub(replace, content)

    def _rewrite_legacy_low_level_calls(self, content: str) -> str:
        pattern = re.compile(
            r"(?P<indent>[ \t]*)"
            r"\(\s*bool\s+(?P<var>\w+)\s*,\s*\)\s*=\s*"
            r"(?P<call>[^\n;]+?\.call(?:\.value\([^\n;]*\))?)\(\"\"\)\s*;"
            r"(?P<comment>[^\n]*)\n"
            r"(?P=indent)require\(\s*(?P=var)\s*\)\s*;",
            re.MULTILINE,
        )

        def replace(match: re.Match[str]) -> str:
            indent = match.group("indent")
            call = match.group("call").strip()
            comment = match.group("comment") or ""
            return f"{indent}require({call}());{comment}"

        return pattern.sub(replace, content)

    def _should_retry_with_compat(self, project_path: str, exc: Exception) -> bool:
        path = Path(project_path)
        if not path.is_file() or path.name.endswith(self._compat_suffix):
            return False

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return False

        return self._rewrite_compat_content(content) != content

    def _write_compat_file(self, project_path: str) -> Optional[str]:
        source_path = Path(project_path)
        try:
            original = source_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None

        rewritten = self._rewrite_compat_content(original)
        if rewritten == original:
            return None

        compat_name = f".{source_path.stem}{self._compat_suffix}"
        compat_path = source_path.with_name(compat_name)
        try:
            compat_path.write_text(rewritten, encoding="utf-8")
            return str(compat_path)
        except OSError:
            compat_root = Path.cwd() / ".tmp_slither_compat"
            compat_root.mkdir(parents=True, exist_ok=True)
            compat_path = compat_root / f"{source_path.parent.name}__{source_path.stem}{self._compat_suffix}"
            compat_path.write_text(rewritten, encoding="utf-8")
            return str(compat_path)
    
    def load_project(self, project_path: str) -> Any:
        """
        加载Solidity项目
        
        Args:
            project_path: 项目路径（文件或目录）
            
        Returns:
            Slither 实例
        """
        try:
            self.slither = self._load_with_slither(project_path)
            print(f"[+] Slither initialized successfully!")
            contracts = [c.name for c in self.slither.contracts]
            print(f"[+] Found {len(contracts)} contracts: {contracts}")
            return self.slither
        except Exception as e:
            if self._should_retry_with_compat(project_path, e):
                compat_path = self._write_compat_file(project_path)
                if compat_path:
                    print("[!] Retrying Slither with a compatibility-rewritten temporary copy")
                    try:
                        self.slither = self._load_with_slither(compat_path)
                        print(f"[+] Slither initialized successfully!")
                        contracts = [c.name for c in self.slither.contracts]
                        print(f"[+] Found {len(contracts)} contracts: {contracts}")
                        return self.slither
                    finally:
                        try:
                            Path(compat_path).unlink(missing_ok=True)
                        except OSError:
                            pass
            print(f"[-] Failed to load project: {e}")
            raise
    
    def load_file(self, file_path: str) -> Any:
        """
        加载单个 Solidity 文件
        
        Args:
            file_path: 文件路径
            
        Returns:
            Slither 实例
        """
        return self.load_project(file_path)
    
    def get_contracts(self) -> List[Any]:
        """获取加载的所有合约"""
        if self.slither is None:
            raise RuntimeError("Slither not loaded. Call load_project() or load_file() first.")
        return self.slither.contracts
    
    def get_compilation_info(self) -> Dict[str, Any]:
        """获取编译信息"""
        if self.slither is None:
            raise RuntimeError("Slither not loaded. Call load_project() or load_file() first.")
        return {
            "contracts_count": len(self.slither.contracts),
            "solc_version": self.slither.solc_version if hasattr(self.slither, 'solc_version') else None,
            "pragma": self.slither.pragma if hasattr(self.slither, 'pragma') else None,
        }
    
    def export_contracts_info(self) -> Dict[str, Dict[str, Any]]:
        """
        导出所有合约信息
        
        Returns:
            合约信息字典，格式: {contract_name: {functions, state_variables, ...}}
        """
        if self.slither is None:
            return {}
        
        result = {}
        for contract in self.slither.contracts:
            result[contract.name] = {
                "functions": self._export_functions(contract),
                "state_variables": self._export_state_vars(contract),
                "parent_classes": [p.name for p in contract.inheritance if hasattr(p, 'name')],
            }
        return result
    
    def _export_functions(self, contract: Contract) -> Dict[str, Dict[str, Any]]:
        """导出合约的所有函数信息"""
        result = {}
        for func in contract.functions:
            result[func.name] = {
                "is_constructor": func.is_constructor,
                "visibility": func.visibility,
                "state_mutability": func.state_mutability,
                "state_variables_read": [sv.name for sv in func.state_variables_read],
                "state_variables_written": [sv.name for sv in func.state_variables_written],
            }
        return result
    
    def _export_state_vars(self, contract: Contract) -> Dict[str, Dict[str, Any]]:
        """导出合约的所有状态变量信息"""
        result = {}
        for sv in contract.state_variables:
            result[sv.name] = {
                "type": str(sv.type),
                "visibility": sv.visibility,
                "is_immutable": sv.is_immutable if hasattr(sv, 'is_immutable') else False,
            }
        return result
