#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from config import normalize_classic_fallback_policy
from models import VulnerabilityReport


class PrecisionFilter:
    """Conservative report-level suppressions for common static-analysis FPs."""

    def __init__(self, classic_fallback_policy: str = "normal"):
        self.classic_fallback_policy = normalize_classic_fallback_policy(classic_fallback_policy)
        self._source_cache: Dict[str, List[str]] = {}

    TOKEN_FUNCTIONS = {
        "approve",
        "burn",
        "burnfrom",
        "burntokens",
        "createtokens",
        "decreaseapproval",
        "deposit",
        "depositerc20",
        "exit",
        "increaseapproval",
        "mint",
        "operatortransfer",
        "stake",
        "transfer",
        "transferfrom",
        "withdraw",
        "withdrawerc20foraddress",
        "withdrawforaddress",
    }

    BALANCE_STATES = {"balances", "_balances", "s_balances"}
    TOKEN_BOOKKEEPING_STATES = {
        "_allowances",
        "_balances",
        "_totalsupply",
        "allowed",
        "allowance",
        "allowances",
        "balance",
        "balanceof",
        "s_allowances",
        "s_balances",
        "tokensbalance",
        "tokenswithdrawalallowanceforaddress",
        "totalsupply",
        "totalsupply_",
        "withdrawalallowanceforaddress",
    }

    PROXY_BOOKKEEPING_STATES = {
        "_implementations",
        "_lastimplementation",
        "arguments",
        "deployed",
        "initialized",
    }

    DEX_CONFIG_STATES = {
        "allpairs",
        "getpair",
        "klast",
        "uniswapv2pair",
        "uniswapv2router",
    }

    REWARD_BOOKKEEPING_STATES = {
        "firstreward",
        "lastrewardid",
        "lastupdatetime",
        "periodfinish",
        "rewardrate",
        "rewards",
    }

    LOCK_BOOKKEEPING_STATES = {
        "blockedbalance",
        "blockedtokensbalance",
        "blocked_for_single_sig_withdrawal",
        "locked",
        "unlocked",
    }

    READONLY_BOOKKEEPING_STATES = {
        "accounts",
        "baserateperblock",
        "availabletokens",
        "burn",
        "contractstakers",
        "currentorderid",
        "currentproposal",
        "flashloanindex",
        "fundaccounts",
        "intentreceipt",
        "istokentransferable",
        "max_exposure",
        "market",
        "matched",
        "min_stake",
        "min_unstake",
        "multiplierperblock",
        "orders",
        "processedtostakerindex",
        "projects",
        "projectmilestones",
        "stage",
        "stakers",
        "tobedistributed",
        "tokenholders",
        "unstake_lock_time",
        "unstakerequests",
        "upgradeagent",
        "virtualprice",
        "votes",
    }

    CROWDSALE_BOOKKEEPING_STATES = {
        "allocatedeth",
        "contributorlist",
        "finalized",
        "isfinalized",
        "istokentransferable",
        "raised",
        "stage",
        "tokenamountof",
        "tokenholders",
    }

    ADMIN_BOOKKEEPING_STATES = {
        "_isexcludedfromfee",
        "fundaccounts",
        "owner",
        "tokenapprovals",
    }

    PLAYER_BOOKKEEPING_STATES = {
        "games_",
        "gid_",
        "pidxaddr_",
        "pidxname_",
        "plyr_",
        "round_",
    }

    MULTISIG_BOOKKEEPING_STATES = {"transactions"}
    AFFILIATE_BOOKKEEPING_STATES = {"affiliatebalance", "totalaffiliatebalance"}
    VAULT_BOOKKEEPING_STATES = {"withdrawalbacklog"}
    POOL_BOOKKEEPING_STATES = {"poolinfo"}

    ETH_VALUE_MARKERS = (
        ".call.value",
        ".send(",
        "{value:",
        ".value(",
        ".value.",
        "safetransfereth",
        "sendvalue",
        "transfereth",
    )

    TOKEN_TRANSFER_MARKERS = (
        "safetransfer(",
        "safetransferfrom(",
        "transferfrom(",
    )

    TOKEN_OBJECT_MARKERS = (
        "erc20",
        "token",
        "usdc",
        "usdt",
        "usdtoken",
        "dai",
        "busd",
        "stakingpool.token()",
        "lockedpool",
        "unlockedpool",
    )

    PURE_LIBRARY_MARKERS = (
        "abi.encode",
        "keccak256",
        "sha3",
        ".add(",
        ".sub(",
        ".mul(",
        ".div(",
        ".plus(",
        ".minus(",
    )

    PURE_LIBRARY_CALL_NAMES = {
        "add",
        "div",
        "encode",
        "encodepacked",
        "keccak256",
        "minus",
        "mul",
        "plus",
        "sha3",
        "sub",
    }

    READONLY_CALL_NAMES = {
        "allowance",
        "balanceof",
        "calculateprice",
        "decimals",
        "finalized",
        "getplayerid",
        "latestanswer",
        "latestrounddata",
        "memberatindex",
        "name",
        "owner",
        "ownerof",
        "paused",
        "read",
        "addressmanager",
        "blockhashmapping",
        "rolemanager",
        "symbol",
        "tokenaddress",
        "totalsupply",
    }

    READONLY_CALL_PREFIXES = (
        "calc",
        "calculate",
        "can",
        "check",
        "current",
        "get",
        "has",
        "is",
        "latest",
        "query",
    )

    STATE_CHANGING_CALL_HINTS = (
        "addliquidity",
        "borrow",
        "burn",
        "claim",
        "deposit",
        "execute",
        "finalizecrowdsale",
        "fund",
        "issue",
        "liquidate",
        "mint",
        "redeem",
        "swap",
        "transfer",
        "withdraw",
    )

    DEX_BUSINESS_MARKERS = (
        "dexblue",
        "uniswapv2router.",
        "pancakerouter.",
        "pancakeswaprouter.",
        "sushiswaprouter.",
    )

    CROWDSALE_TOKEN_LIFECYCLE_MARKERS = (
        ".issue(",
        ".maximum_supply(",
        ".mint(",
        "finalizecrowdsale(",
        "token.issue(",
        "token.mint(",
        "token.unlock(",
        "updateearlyparticipantwhitelist(",
        "vault.close(",
    )

    ADMIN_CALL_MARKERS = (
        "assignburner(",
        "assignoperator(",
        "excludefromfee(",
        "proxyregistry.proxies(",
        "setexcludefromfee(",
        "transferownership(",
    )

    PLAYER_REFERRAL_MARKERS = (
        "address(admin).call.value",
        "companyshare.deposit",
        "fundforwardermain",
        "playerbook",
        "receiveplayerinfo",
    )

    MULTISIG_CALL_MARKERS = ("tx.destination.call.value",)
    AFFILIATE_PAYOUT_MARKERS = ("sendvalue",)
    VAULT_BACKLOG_MARKERS = ("atoken.redeem(", "charityvault.deposit.value")
    POOL_TOKEN_TRANSFER_MARKERS = ("cake.transfer(", "rgb.transfer(")

    STRATEGY_MAINTENANCE_MARKERS = (
        ".safeapprove(",
        ".redeemidletoken(",
        ".releaselockedtokens(",
        ".pushburnedtokens(",
        "claimsreward._claimstakecommission(",
        "horseytoken(",
        "milestonescontract.terminatelastmilestone(",
        "projectscontract.completeproject(",
        "spender.claimtokens(",
        "token.burn(",
        "tokencontroller.addtowhitelist(",
        "tokencontroller.releaselockedtokens(",
    )

    DYNAMIC_LOW_LEVEL_MARKERS = (
        "call_data",
        "calldata",
        "msg.sender",
        "target",
        "tx.origin",
    )

    ADMIN_RECOVERY_FUNCTIONS = {
        "claimownership",
        "kill",
        "renounceownership",
        "recover",
        "recovererc20",
        "recoverstucketh",
        "rescue",
        "rescueerc20",
        "rescuetoken",
        "sweep",
        "sweeptoken",
        "transferownership",
        "withdrawstucketh",
    }

    ADMIN_RECOVERY_PREFIXES = (
        "admin",
        "emergency",
        "recover",
        "rescue",
        "setowner",
        "settrader",
        "sweep",
        "withdrawstuck",
    )

    ADMIN_PAYOUT_MARKERS = (
        "owner()",
        "address(owner())",
        "platformaccount.call",
        "treasury",
        "admin",
    )

    RECOVERY_TOKEN_MARKERS = (
        ".safeapprove(",
        ".safetransfer(",
        ".safetransferfrom(",
        ".transfer(",
        ".transferfrom(",
    )

    ADMIN_CONFIG_TARGET_PREFIXES = (
        "amnesty",
        "change",
        "enable",
        "exclude",
        "init",
        "launch",
        "manual",
        "open",
        "owner",
        "remove",
        "set",
        "update",
        "whitelist",
    )

    ADMIN_CONFIG_TARGETS = {
        "addliquidity",
        "launch",
    }

    ADMIN_CONFIG_STATE_MARKERS = (
        "blacklist",
        "contract_balance",
        "dev",
        "exclude",
        "excluded",
        "fee",
        "limit",
        "marketing",
        "max",
        "pair",
        "presale",
        "router",
        "sniper",
        "swap",
        "tax",
        "trading",
        "wallet",
        "whitelist",
    )

    ADMIN_GUARD_MARKERS = (
        "onlyadmin",
        "onlyauthorized",
        "onlycontroller",
        "onlyoperator",
        "onlyowner",
    )

    STRICT_FIXED_RECEIVER_MARKERS = (
        "dev",
        "feewallet",
        "marketing",
        "taxwallet",
        "uniswap",
    )

    STRICT_MARKETPLACE_RECEIVER_MARKERS = (
        "_royaltyrecipient",
        "_seller",
        "platformaccount",
        "safetransferfrom",
    )

    STRICT_MARKETPLACE_TARGET_MARKERS = (
        "accepteditionbid",
        "accepttokenbid",
        "reserveauction",
    )

    STRICT_ESCROW_SAFE_GAS_STATES = (
        "availablecount",
        "escrows",
        "feefunds",
        "pendingcount",
        "totalescrows",
    )

    STRICT_MULTISIG_EXEC_STATES = (
        "m_lastday",
        "m_pending",
        "m_spenttoday",
        "m_txs",
    )

    ROR_EXTERNAL_CONSUMER = "__external_readonly_consumer__"
    ROR_READ_GUARD_STATES = {
        "locked",
        "updating",
        "settling",
    }
    ROR_FINALIZED_QUERY_MARKERS = (
        "finalized",
        "previous",
        "committed",
    )
    ROR_NOTIFICATION_CALL_MARKERS = (
        ".after",
        ".beforecommit",
        ".notify(",
        ".onindexupdated(",
        ".refresh(",
    )
    ROR_INERT_HOOK_CALL_MARKERS = (
        ".onexit(",
        ".ondeposit(",
        ".onwithdraw(",
    )

    def filter_reports(
        self,
        reports: List[VulnerabilityReport],
    ) -> Tuple[List[VulnerabilityReport], List[Tuple[VulnerabilityReport, str]]]:
        kept: List[VulnerabilityReport] = []
        dropped: List[Tuple[VulnerabilityReport, str]] = []

        for report in reports:
            reason = self.drop_reason(report)
            if reason:
                dropped.append((report, reason))
            else:
                kept.append(report)

        return kept, dropped

    def drop_reason(self, report: VulnerabilityReport) -> Optional[str]:
        if report.is_ror():
            return self._drop_reason_ror(report)

        if not report.is_ccr():
            return None

        expression = self._external_call_expression(report)
        if "address(this).call" in expression:
            return "self-call dispatch is not attacker callback controlled"

        states = self._normalized_states(report)
        if not states:
            return None

        if self._is_nonreentrant_guard_bookkeeping(states):
            return "nonReentrant guard bookkeeping state is not vulnerable accounting"
        if self._is_protocol_queue_bookkeeping(report, states, expression):
            return "protocol-owned priority queue bookkeeping without attacker-controlled callback"
        if self._is_uniswap_v3_guarded_pool_callback(report, states, expression):
            return "Uniswap V3 pool lock/oracle bookkeeping without exploitable callback"
        if self._is_trusted_protocol_accounting_call(report, states, expression):
            return "trusted protocol accounting/read dependency without attacker-controlled callback"

        if self._is_strict_dividend_tracker_config_call(report, states, expression):
            return "strict dividend tracker configuration call without attacker-controlled callback"
        if self._is_strict_weak_classic_fallback(report, expression):
            return "strict classic fallback: fixed admin/DEX receiver without attacker-controlled callback"
        if self._is_guarded_admin_config_callback(report, states):
            return "guarded admin/config callback target is not attacker reachable"
        if states <= self.DEX_CONFIG_STATES:
            return "DEX configuration/cache state without attacker-controlled accounting"
        if self._has_eth_value_transfer(expression) or self._is_dynamic_low_level_call(expression):
            if self._is_admin_recovery_fallback(report, expression):
                return "admin/recovery classic fallback payout without attacker-controlled callback"
            if self._is_dex_business_call(report, expression):
                return "DEX/router settlement bookkeeping without attacker-controlled ETH callback"
            if self._is_player_referral_bookkeeping(report, states, expression):
                return "player/referral bookkeeping payout without attacker-controlled accounting"
            if self._is_multisig_bookkeeping(report, states, expression):
                return "multisig transaction bookkeeping without vulnerable account state"
            if self._is_affiliate_bookkeeping(states, expression):
                return "affiliate bookkeeping payout without vulnerable account state"
            if self._is_vault_backlog_bookkeeping(states, expression):
                return "vault backlog bookkeeping without vulnerable account state"
            return None

        if self._is_token_approval_fallback(report, expression):
            return "token approval classic fallback without callback-capable external call"
        if self._is_admin_recovery_fallback(report, expression):
            return "admin/recovery classic fallback without attacker-controlled callback"
        if self._is_blank_or_unresolved_token_bookkeeping(report, states, expression):
            return "unresolved token bookkeeping call without callback evidence"
        if self._is_dex_business_call(report, expression):
            return "DEX/router settlement bookkeeping without attacker-controlled callback"
        if self._is_crowdsale_token_lifecycle(states, expression):
            return "crowdsale/token lifecycle bookkeeping without attacker-controlled callback"
        if self._is_admin_bookkeeping(states, expression):
            return "admin/operator bookkeeping without attacker-controlled callback"
        if self._is_player_referral_bookkeeping(report, states, expression):
            return "player/referral bookkeeping without attacker-controlled callback"
        if self._is_multisig_bookkeeping(report, states, expression):
            return "multisig transaction bookkeeping without vulnerable account state"
        if self._is_affiliate_bookkeeping(states, expression):
            return "affiliate bookkeeping payout without vulnerable account state"
        if self._is_vault_backlog_bookkeeping(states, expression):
            return "vault backlog bookkeeping without vulnerable account state"
        if self._is_pool_bookkeeping_transfer(states, expression):
            return "pool bookkeeping token transfer without ETH-valued callback"
        if self._is_strategy_maintenance_call(states, expression):
            return "strategy/maintenance bookkeeping without attacker-controlled callback"
        if self._is_token_bookkeeping(report, states):
            return "token bookkeeping state without ETH-valued callback"
        if self._is_pure_library_expression(expression):
            return "pure/library computation is not attacker callback controlled"
        if self._is_readonly_query_expression(expression):
            return "read-only query call without ETH-valued callback"
        if self._is_token_transfer_expression(report, states, expression):
            return "token transfer call without ETH-valued callback"
        if states & self.PROXY_BOOKKEEPING_STATES:
            return "proxy/admin bookkeeping state without ETH-valued callback"
        if states & self.DEX_CONFIG_STATES:
            return "DEX configuration/cache state without ETH-valued callback"
        if states & self.REWARD_BOOKKEEPING_STATES:
            return "reward accounting state without ETH-valued callback"
        if states & self.LOCK_BOOKKEEPING_STATES:
            return "lock/timelock bookkeeping state without ETH-valued callback"
        if states <= self.READONLY_BOOKKEEPING_STATES:
            return "read-only bookkeeping state without ETH-valued callback"

        return None

    def _drop_reason_ror(self, report: VulnerabilityReport) -> Optional[str]:
        if report.sink_function != self.ROR_EXTERNAL_CONSUMER:
            return None

        states = self._normalized_states(report)
        expression = self._ror_evidence_expression(report)
        query = self._normalize(report.query_function)
        window_id = self._normalize((report.mismatch_window or {}).get("window_id"))

        if states & self.ROR_READ_GUARD_STATES:
            return "read-only query is guarded by an explicit update/read lock"

        if any(marker in query for marker in self.ROR_FINALIZED_QUERY_MARKERS):
            return "query returns finalized/snapshot state rather than the in-progress state"

        if any(marker in expression for marker in self.ROR_NOTIFICATION_CALL_MARKERS):
            return "external call is a notification/refresh hook without evidence of attacker-controlled read consumption"

        if "stale_window" in window_id and any(
            marker in expression for marker in self.ROR_INERT_HOOK_CALL_MARKERS
        ):
            return "external hook has no evidence of consuming the stale read-only value"

        if self._is_strict_weak_ror_external_consumer(report, states, expression, query):
            return "strict ROR external consumer is a configuration/accounting query without exploitable stale read"

        if self._is_strict_weak_ror_bookkeeping_window(report, states):
            return "strict ROR bookkeeping window without exploitable stale read"

        if self._is_uniswap_v3_guarded_pool_ror(report, states, expression, query):
            return "Uniswap V3 guarded pool oracle/read window without exploitable stale read"

        if self._is_protocol_view_ror(report, states, query):
            return "protocol view/length query without exploitable stale read"

        return None

    def _ror_evidence_expression(self, report: VulnerabilityReport) -> str:
        expressions = [
            self._normalize(node.get("expression"))
            for node in report.evidence_path
            if isinstance(node, dict)
        ]
        return " ".join(expression for expression in expressions if expression)

    def _is_strict_weak_ror_external_consumer(
        self,
        report: VulnerabilityReport,
        states: set[str],
        expression: str,
        query: str,
    ) -> bool:
        if self.classic_fallback_policy not in {"strict", "aggressive"}:
            return False
        if report.sink_function != self.ROR_EXTERNAL_CONSUMER:
            return False
        if states <= {"incrementtime", "maxbuyincrementvalue"}:
            return "addliquidityeth" in expression and query.endswith("getmaxbuy")
        if states <= {"transactions"}:
            return "tx.destination.call.value" in expression and any(
                query.endswith(name) for name in ("gettransactioncount", "gettransactionids")
            )
        return False

    def _is_strict_weak_ror_bookkeeping_window(
        self, report: VulnerabilityReport, states: set[str]
    ) -> bool:
        if self.classic_fallback_policy not in {"strict", "aggressive"}:
            return False
        if report.sink_function != self.ROR_EXTERNAL_CONSUMER:
            return False

        source = self._normalize(report.source_function)
        if source == "constructor" and states <= {"_balances", "balances"}:
            return True
        if source in {"intializecontract", "initializecontract"} and (
            states & {"_decimals", "_allowances", "_symbol", "_ttotal", "_maxtxamount", "_maxwalletsize"}
        ):
            return True
        if source == "opentrading" and states <= {"_allowances"}:
            return True
        if "airdrop" in source and states <= {"_buymap"}:
            return True
        if source.startswith("unlock") and states <= {"holderlist"}:
            return True
        if source.startswith("transferto") and states <= {"recievermap", "receivermap"}:
            return True
        if source in {"transfer", "transferfrom", "_transfer"} and states <= {
            "balances",
            "_balances",
            "allowed",
            "_allowances",
        }:
            return True
        if source == "tokenfallback" and states <= {"deadline"}:
            return True
        if states <= {"campaigns"} and any(marker in source for marker in ("campaign", "sendcoin")):
            return True
        if source == "vote" and states <= {"proposals"}:
            return True
        if "dividendofuser" in source and states <= {"withdrawndividends", "totaldividendswithdrawn"}:
            return True
        if source.startswith("update") and "dividendtracker" in self._normalize(report.source_contract) and states <= {
            "dividendtracker",
            "withdrawndividends",
            "lastprocessedindex",
        }:
            return True
        if "dividendtracker" in self._normalize(report.source_contract) and source == "process" and states <= {
            "dividendtracker",
            "withdrawndividends",
            "lastprocessedindex",
        }:
            return True
        if "withdrawdividendofuser" in source and states <= {"withdrawndividends"}:
            return True
        if source == "fallback" and states <= {"balances", "_balances"}:
            return True
        if source in {"finalizeround", "startround"} and states <= {"currentround"}:
            return True
        if source in {"_transfer", "transferadmin"} and states <= {"_totalsupply", "_isexcludedfromfees"}:
            return True
        if source == "_rft" and states <= {"_rod", "_als", "_decimals"}:
            return True
        if source in {"investinternal", "preallocate", "buyforeverybody", "finalize"} and (
            states & {"weiraised", "tokensbought", "finalized"}
        ):
            return True
        if source in {"takeether", "givetoken", "refundether", "rc", "rcpro", "settimerc", "settime"} and (
            states & {
                "etheruser",
                "pendingtokenuser",
                "remainingtokens",
                "soldtokens",
                "starttime",
                "endtime",
                "onetokeninfiatwei",
            }
        ):
            return True
        return False

    def _is_token_bookkeeping(self, report: VulnerabilityReport, states: set[str]) -> bool:
        source = self._normalize(report.source_function)
        target = self._normalize(report.target_function)

        if states <= self.TOKEN_BOOKKEEPING_STATES:
            return True

        if not (states & self.BALANCE_STATES):
            return False
        if not (source in self.TOKEN_FUNCTIONS and target in self.TOKEN_FUNCTIONS):
            return False

        non_balance_states = states - self.BALANCE_STATES
        return non_balance_states <= self.TOKEN_BOOKKEEPING_STATES

    def _is_blank_or_unresolved_token_bookkeeping(
        self, report: VulnerabilityReport, states: set[str], expression: str
    ) -> bool:
        if expression:
            return False
        if not (states & {"allowed", "allowance", "balances", "tokenapprovals"}):
            return False
        source = self._normalize(report.source_function)
        target = self._normalize(report.target_function)
        return source in self.TOKEN_FUNCTIONS or target in self.TOKEN_FUNCTIONS or not target

    def _is_dex_business_call(self, report: VulnerabilityReport, expression: str) -> bool:
        contract_text = self._normalize(report.source_contract) + self._normalize(report.target_contract)
        function_text = self._normalize(report.source_function) + self._normalize(report.target_function)
        if any(marker in expression for marker in self.DEX_BUSINESS_MARKERS):
            return True
        return "dexblue" in contract_text or (
            any(name in function_text for name in ("settle", "swap", "trade"))
            and any(name in function_text for name in ("reserve", "blockfunds"))
        )

    def _is_crowdsale_token_lifecycle(self, states: set[str], expression: str) -> bool:
        if not any(marker in expression for marker in self.CROWDSALE_TOKEN_LIFECYCLE_MARKERS):
            return False
        lifecycle_states = states & self.CROWDSALE_BOOKKEEPING_STATES
        token_supply_states = states & {
            "availabletokens",
            "balances",
            "contributorlist",
            "index",
            "tokenholders",
        }
        return bool(lifecycle_states or token_supply_states)

    def _is_admin_bookkeeping(self, states: set[str], expression: str) -> bool:
        if not any(marker in expression for marker in self.ADMIN_CALL_MARKERS):
            return False
        return bool(states & self.ADMIN_BOOKKEEPING_STATES)

    def _is_player_referral_bookkeeping(
        self, report: VulnerabilityReport, states: set[str], expression: str
    ) -> bool:
        if not (states & self.PLAYER_BOOKKEEPING_STATES):
            return False
        if any(marker in expression for marker in self.PLAYER_REFERRAL_MARKERS):
            return True
        function_text = self._normalize(report.source_function) + self._normalize(report.target_function)
        return any(name in function_text for name in ("buyx", "activate", "addgame"))

    def _is_multisig_bookkeeping(
        self, report: VulnerabilityReport, states: set[str], expression: str
    ) -> bool:
        if not (states & self.MULTISIG_BOOKKEEPING_STATES):
            return False
        if not any(marker in expression for marker in self.MULTISIG_CALL_MARKERS):
            return False
        function_text = self._normalize(report.source_function) + self._normalize(report.target_function)
        return any(name in function_text for name in ("transaction", "confirm"))

    def _is_affiliate_bookkeeping(self, states: set[str], expression: str) -> bool:
        return bool(states & self.AFFILIATE_BOOKKEEPING_STATES) and any(
            marker in expression for marker in self.AFFILIATE_PAYOUT_MARKERS
        )

    def _is_vault_backlog_bookkeeping(self, states: set[str], expression: str) -> bool:
        return bool(states & self.VAULT_BOOKKEEPING_STATES) and any(
            marker in expression for marker in self.VAULT_BACKLOG_MARKERS
        )

    def _is_pool_bookkeeping_transfer(self, states: set[str], expression: str) -> bool:
        return bool(states & self.POOL_BOOKKEEPING_STATES) and any(
            marker in expression for marker in self.POOL_TOKEN_TRANSFER_MARKERS
        )

    def _is_strategy_maintenance_call(self, states: set[str], expression: str) -> bool:
        maintenance_states = states & (
            self.READONLY_BOOKKEEPING_STATES
            | {
                "contract_balance",
                "contractstakers",
                "processedtostakerindex",
                "projects",
                "projectmilestones",
                "stakers",
                "unstakerequests",
            }
        )
        if not maintenance_states:
            return False
        return any(marker in expression for marker in self.STRATEGY_MAINTENANCE_MARKERS)

    def _is_nonreentrant_guard_bookkeeping(self, states: set[str]) -> bool:
        return bool(states & {"_guardcounter", "reentrancylock"})

    def _is_protocol_queue_bookkeeping(
        self, report: VulnerabilityReport, states: set[str], expression: str
    ) -> bool:
        if states - {"delegations"}:
            return False
        expression = self._compact_expression(expression)
        if "queue.insert(" not in expression:
            return False
        contract_text = self._normalize(report.source_contract) + self._normalize(report.target_contract)
        function_text = self._normalize(report.source_function) + self._normalize(report.target_function)
        return (
            "plasmaframework" in contract_text
            or "exitgamecontroller" in contract_text
            or "enqueue" in function_text
        )

    def _is_uniswap_v3_guarded_pool_callback(
        self, report: VulnerabilityReport, states: set[str], expression: str
    ) -> bool:
        contract_text = self._normalize(report.source_contract) + self._normalize(report.target_contract)
        if "uniswapv3pool" not in contract_text:
            return False
        guarded_states = {
            "slot0",
            "liquidity",
            "protocolfees",
            "feegrowthglobal0x128",
            "feegrowthglobal1x128",
        }
        if states and states <= guarded_states:
            return True
        expression = self._compact_expression(expression)
        return any(
            marker in expression
            for marker in (
                "uniswapv3mintcallback(",
                "uniswapv3swapcallback(",
                "ticks.cross(",
                "secondsoutside.cross(",
                "observations.",
            )
        )

    def _is_trusted_protocol_accounting_call(
        self, report: VulnerabilityReport, states: set[str], expression: str
    ) -> bool:
        expression = self._compact_expression(expression)
        contract_text = self._normalize(report.source_contract) + self._normalize(report.target_contract)
        target = self._normalize(report.target_function)

        if "stabilitypool" in contract_text and states <= {"eth", "deposits", "totallusddeposits"}:
            return True
        if "holdefisettings" in contract_text and any(
            marker in expression
            for marker in (
                "holdeficontract.beforechangeborrowrate(",
                "holdeficontract.beforechangesupplyrate(",
            )
        ):
            return True
        if "sigmoidcuratorvault" in contract_text and states <= {"curatortokensupply", "reserves"}:
            return any(
                marker in expression
                for marker in (
                    "addressmanager.rolemanager().is",
                    "addressmanager.parametermanager().bondingcurveparams()",
                    "paymenttoken.safetransferfrom(msg.sender,address(this)",
                )
            )
        if "blockregistry.blockhashmapping(" in expression:
            return True
        if "rolemanager().is" in expression or ".rolemanager().is" in expression:
            return True
        if "wrap.withdraw()" in expression and states <= {"_isexcludedfromfee"}:
            return True
        if "communityissuance.issuelqty()" in expression and "totallusddeposits" in states:
            return target == "offset" or "stabilitypool" in contract_text
        if "pricefeed.fetchprice()" in expression and "totallusddeposits" in states:
            return target == "offset" or "stabilitypool" in contract_text
        return False

    def _is_uniswap_v3_guarded_pool_ror(
        self,
        report: VulnerabilityReport,
        states: set[str],
        expression: str,
        query: str,
    ) -> bool:
        if "uniswapv3pool" not in self._normalize(report.source_contract):
            return False
        if not any(query.endswith(name) for name in ("observe", "secondsinside")):
            return False
        return bool(states) and states <= {"slot0", "liquidity", "protocolfees"}

    def _is_protocol_view_ror(
        self, report: VulnerabilityReport, states: set[str], query: str
    ) -> bool:
        source = self._normalize(report.source_function)
        contract = self._normalize(report.source_contract)
        if (
            "waultswapfactory" in contract
            and states <= {"allpairs"}
            and query.endswith("allpairslength")
        ):
            return True
        if (
            "stabilitypool" in contract
            and states <= {"totallusddeposits"}
            and query.endswith("gettotallusddeposits")
        ):
            return True
        if states <= {"stakes"} and query.endswith("getstakes"):
            return source in {"_stake", "stake"}
        if states <= {"stakes"} and any(query.endswith(name) for name in ("balanceof", "available")):
            return source in {"_stake", "stake"}
        if states <= {"marketassets"} and query.endswith("getinterests"):
            return source.startswith("set") or source == "removemarket"
        if states <= {"marketslist"} and query.endswith("getmarketslist"):
            return source == "removemarket"
        return False

    def _is_token_approval_fallback(self, report: VulnerabilityReport, expression: str) -> bool:
        if not self._is_classic_fallback(report):
            return False
        if self._has_callback_capable_call(expression):
            return False
        return ".approve(" in expression or ".safeapprove(" in expression

    def _is_admin_recovery_fallback(self, report: VulnerabilityReport, expression: str) -> bool:
        if not self._is_classic_fallback(report):
            return False

        source = self._normalize(report.source_function)
        if not self._is_admin_recovery_function(source):
            return False

        if self._has_eth_value_transfer(expression) or self._is_dynamic_low_level_call(expression):
            return any(marker in expression for marker in self.ADMIN_PAYOUT_MARKERS)

        if source.startswith(("recover", "rescue", "sweep", "withdrawstuck")):
            return any(marker in expression for marker in self.RECOVERY_TOKEN_MARKERS)

        return False

    def _is_classic_fallback(self, report: VulnerabilityReport) -> bool:
        callback_entry = report.callback_entry or {}
        return self._normalize(callback_entry.get("kind")) == "classic"

    def _is_admin_recovery_function(self, name: str) -> bool:
        return name in self.ADMIN_RECOVERY_FUNCTIONS or any(
            name.startswith(prefix) for prefix in self.ADMIN_RECOVERY_PREFIXES
        )

    def _is_guarded_admin_config_callback(
        self, report: VulnerabilityReport, states: set[str]
    ) -> bool:
        if not self._is_classic_fallback(report):
            return False

        target = self._normalize(report.target_function)
        if not target:
            return False
        if not (
            target in self.ADMIN_CONFIG_TARGETS
            or target.startswith(self.ADMIN_CONFIG_TARGET_PREFIXES)
        ):
            return False
        if not any(
            any(marker in state for marker in self.ADMIN_CONFIG_STATE_MARKERS)
            for state in states
        ):
            return False

        signature = self._function_signature_text(report, report.target_function)
        return any(marker in signature for marker in self.ADMIN_GUARD_MARKERS)

    def _is_strict_weak_classic_fallback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if self.classic_fallback_policy not in {"strict", "aggressive"}:
            return False
        if not self._is_classic_fallback(report):
            return False
        fixed_receiver = "msg.sender" not in expression and any(
            marker in expression for marker in self.STRICT_FIXED_RECEIVER_MARKERS
        )
        return fixed_receiver or (
            self._has_status_state(report)
            and self._is_marketplace_settlement_fallback(report, expression)
        ) or (
            self._is_status_only(report)
            and (
                "address(destination).call{value:" in expression
                or ".transfer(msg.sender" in expression
            )
        ) or self._is_allowance_decrease_fallback(report) or (
            "addr.call.gas(safegas).value(value)" in expression
            and bool(self._normalized_states(report) & set(self.STRICT_ESCROW_SAFE_GAS_STATES))
        ) or self._is_surcharge_reset_fallback(report) or self._is_liquidity_lock_fallback(
            report, expression
        ) or self._is_blacklist_distribution_fallback(
            report, expression
        ) or self._is_guarded_transfer_eth_fallback(report) or self._is_multisig_execution_fallback(
            report, expression
        ) or self._is_recovery_self_callback(report, expression) or self._is_token_sale_self_callback(
            report, expression
        ) or self._is_fixed_recipient_token_lifecycle_self_callback(
            report, expression
        ) or self._is_authorization_config_self_callback(
            report, expression
        ) or self._is_fixed_recipient_reward_transfer_callback(
            report, expression
        ) or self._is_fixed_fee_collector_self_callback(
            report, expression
        ) or self._is_dai_deposit_transfer_self_callback(
            report, expression
        ) or self._is_status_guarded_inbound_token_transfer(report, expression) or self._is_dividend_tracker_config_callback(
            report, expression
        ) or self._is_protocol_bookkeeping_callback(
            report, expression
        ) or self._is_external_token_lifecycle_callback(
            report, expression
        ) or self._is_airdrop_recipient_distribution_callback(
            report, expression
        ) or self._is_token_manager_storage_callback(
            report, expression
        ) or self._is_router_tax_admin_callback(
            report, expression
        ) or self._is_admin_full_balance_self_callback(
            report, expression
        ) or self._is_value_passthrough_self_callback(
            report, expression
        ) or self._is_drain_full_balance_self_callback(
            report, expression
        ) or self._is_unlock_token_holder_callback(
            report, expression
        ) or self._is_router_liquidity_bootstrap_callback(
            report, expression
        ) or self._is_logevent_delegatecall_callback(
            report, expression
        ) or self._is_fixed_literal_distribution_callback(
            report, expression
        ) or self._is_reentrancy_lock_cash_change_callback(
            report, expression
        ) or self._is_multisig_m_txs_execution_callback(
            report, expression
        ) or self._is_business_lifecycle_callback(
            report, expression
        ) or self._is_aggressive_weak_classic_fallback(report, expression)

    def _is_strict_dividend_tracker_config_call(
        self, report: VulnerabilityReport, states: set[str], expression: str
    ) -> bool:
        if self.classic_fallback_policy not in {"strict", "aggressive"}:
            return False
        expression = self._compact_expression(expression)
        if "dividendtracker.excludefromdividends" not in expression:
            return False
        return bool(states & {"excludedfromdividends", "_owner"})

    def _is_aggressive_weak_classic_fallback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if self.classic_fallback_policy != "aggressive":
            return False
        target = self._normalize(report.target_function)
        return (
            target == "drain"
            or target.startswith("withdraw")
            or ("fee" in expression and "msg.sender" not in expression)
            or "mooninccontract.handleproduction" in expression
            or "itoken(token).mint" in expression
            or "itoken(token).start" in expression
            or "synthetix.issuesynths" in expression
            or "synthetix.burnsynths" in expression
            or "ierc20(_fromtoken).transfer" in expression
            or "require(shitcoin.transfer" in expression
            or "router.addliquidityeth" in expression
            or "router.swapexacttokensforeth" in expression
        )

    def _is_allowance_decrease_fallback(self, report: VulnerabilityReport) -> bool:
        return (
            "_allowances" in self._normalized_states(report)
            and self._normalize(report.target_function) == "decreaseallowance"
        )

    def _is_surcharge_reset_fallback(self, report: VulnerabilityReport) -> bool:
        target = self._normalize(report.target_function)
        return target.startswith("reset") and any(
            "surcharge" in state for state in self._normalized_states(report)
        )

    def _is_liquidity_lock_fallback(self, report: VulnerabilityReport, expression: str) -> bool:
        return (
            self._normalize(report.target_function) == "addliquidity"
            and "m_liquidity" in self._normalized_states(report)
            and "locktokens(" in expression
        )

    def _is_blacklist_distribution_fallback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        return (
            self._normalize(report.target_function) == "disablewhitelist"
            and "blacklist" in self._normalized_states(report)
            and ".transfer(addresses[i]" in expression
        )

    def _is_guarded_transfer_eth_fallback(self, report: VulnerabilityReport) -> bool:
        if self._normalize(report.target_function) != "transfereth":
            return False
        if "contract_balance" not in self._normalized_states(report):
            return False
        signature = self._function_signature_text(report, report.target_function)
        return any(marker in signature for marker in self.ADMIN_GUARD_MARKERS)

    def _is_multisig_execution_fallback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        states = self._normalized_states(report)
        target = self._normalize(report.target_function)
        return (
            "_to.call.value(_value)(_data)" in expression
            and bool(states & set(self.STRICT_MULTISIG_EXEC_STATES))
            and states <= set(self.STRICT_MULTISIG_EXEC_STATES)
            and target in {"execute", "initdaylimit", "resetspenttoday", "revoke"}
        )

    def _is_recovery_self_callback(self, report: VulnerabilityReport, expression: str) -> bool:
        if not self._is_classic_self_callback(report):
            return False

        source = self._normalize(report.source_function)
        states = self._normalized_states(report)
        recovery_name = (
            self._is_admin_recovery_function(source)
            or source in {"claimstucktokens", "collectback", "withdraweth"}
            or source.startswith(("claimstuck", "recover", "rescue", "withdrawstuck"))
        )
        if not recovery_name:
            return False
        if "contract_balance" not in states and not self._has_eth_value_transfer(expression):
            return False
        return (
            "address(this).balance" in expression
            or "address(msg.sender).call" in expression
            or "msg.sender.call.value(address(this).balance)" in expression
            or "address(msg.sender).sendvalue(address(this).balance)" in expression
            or "address(owner).call" in expression
            or "address(owner()).call" in expression
        )

    def _is_token_sale_self_callback(self, report: VulnerabilityReport, expression: str) -> bool:
        if not self._is_classic_self_callback(report):
            return False

        source = self._normalize(report.source_function)
        if source != "fallback":
            return False
        states = self._normalized_states(report)
        sale_states = {
            "amountleft",
            "amountraised",
            "balanceof",
            "fundtransferred",
            "price",
            "raised",
            "soldtokenscounter",
        }
        if not (states & sale_states):
            return False
        return (
            "tokenreward.transfer(msg.sender" in expression
            or "token.transferpresale(msg.sender" in expression
            or "token.transfer(msg.sender" in expression
        )

    def _is_fixed_recipient_token_lifecycle_self_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_self_callback(report):
            return False
        if self._has_eth_value_transfer(expression) or self._is_dynamic_low_level_call(expression):
            return False

        source = self._normalize(report.source_function)
        states = self._normalized_states(report)
        lifecycle_sources = {
            "endsale",
            "finishphase",
            "release",
            "rtbpaymentsprocessing",
        }
        lifecycle_states = {
            "burnedrtbs",
            "contract_balance",
            "lockstatus",
            "netsrevenuertbs",
            "processedrtbs",
            "publrsbudgrtbs",
            "tokensselling",
        }
        fixed_recipient = any(
            marker in expression
            for marker in (
                "transfer(admin",
                "transfer(beneficiary",
                "transfer(_merchantaddress",
                "transfer(abchainpbudgetsaddress",
            )
        )
        return source in lifecycle_sources and bool(states & lifecycle_states) and fixed_recipient

    def _is_authorization_config_self_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_self_callback(report):
            return False
        if "authorize(" not in expression and ".authorize(" not in expression:
            return False

        source = self._normalize(report.source_function)
        states = self._normalized_states(report)
        config_state_markers = ("bounty", "manager", "owner", "wallet")
        config_source = source.startswith(("configure", "set", "update"))
        config_state = any(
            any(marker in state for marker in config_state_markers)
            for state in states
        )
        return config_source or config_state

    def _is_fixed_recipient_reward_transfer_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_fallback(report):
            return False
        if self._has_eth_value_transfer(expression) or self._is_dynamic_low_level_call(expression):
            return False
        if "msg.sender" in expression:
            return False
        if not any(
            marker in expression
            for marker in (
                "tokenreward.transfer(beneficiary",
                "tokenreward.transfer(collectoraddress",
            )
        ):
            return False

        source = self._normalize(report.source_function)
        states = self._normalized_states(report)
        reward_transfer_sources = {"collectback", "safewithdrawal"}
        reward_transfer_states = {"tokenbalance", "totalcandyno"}
        return source in reward_transfer_sources and bool(states & reward_transfer_states)

    def _is_fixed_fee_collector_self_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_self_callback(report):
            return False
        if self._normalized_states(report) != {"balance"}:
            return False
        return "feecollector.call.value(fee)" in expression

    def _is_dai_deposit_transfer_self_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_self_callback(report):
            return False
        if "deposits" not in self._normalized_states(report):
            return False
        if not self._normalize(report.source_function).startswith("deposit"):
            return False
        return (
            "daicontract.transferfrom" in expression
            and "msg.sender" in expression
            and "address(this)" in expression
        )

    def _is_status_guarded_inbound_token_transfer(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_fallback(report):
            return False
        if self._normalized_states(report) != {"_status"}:
            return False
        expression = self._compact_expression(expression)
        return (
            "transferfrom(msg.sender,address(this)" in expression
            or "safetransferfrom(msg.sender,address(this)" in expression
        )

    def _is_dividend_tracker_config_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_fallback(report):
            return False
        expression = self._compact_expression(expression)
        if "dividendtracker." not in expression:
            return False
        return any(
            marker in expression
            for marker in ("excludefromdividends", "updatetokenfordividend")
        )

    def _is_protocol_bookkeeping_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_fallback(report):
            return False
        expression = self._compact_expression(expression)
        return any(
            marker in expression
            for marker in (
                "p3d.withdraw()",
                "p3dcontract.withdraw()",
                "v2pair.sync()",
                "scescrow.deposit(",
                "screfundvault.",
            )
        )

    def _is_external_token_lifecycle_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_fallback(report):
            return False
        expression = self._compact_expression(expression)
        if not any(
            marker in expression
            for marker in (
                "finishminting()",
                "mint(pendingmints",
                "transferownership(newowner)",
                "issuetokens(",
            )
        ):
            return False
        return bool(
            self._normalized_states(report)
            & {"isfinalized", "pendingmints", "balances", "totalsupply"}
        )

    def _is_airdrop_recipient_distribution_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_self_callback(report):
            return False
        expression = self._compact_expression(expression)
        if not any(
            marker in expression
            for marker in (
                "token.transfer(recipient",
                "token.transfer(_recipients",
                "token.transfer(_recipient",
                "token.transfer(_holder",
                "erc20basic(token).transfer(to,val)",
                "sharestokenaddress.transfer(_dests",
            )
        ):
            return False
        return any(
            any(marker in state for marker in ("airdrop", "drop", "claimed", "reciever", "tokenfree"))
            for state in self._normalized_states(report)
        )

    def _is_token_manager_storage_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_fallback(report):
            return False
        expression = self._compact_expression(expression)
        return "_tokenowners.set(" in expression or "authorize(contractname,msg.sender)" in expression

    def _is_router_tax_admin_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_fallback(report):
            return False
        expression = self._compact_expression(expression)
        if "deadaddress" in expression:
            return False
        if not any(
            marker in expression
            for marker in ("router.", "_router.", "univ2router.", "dexrouter.", "uniswapv2router.")
        ):
            return False
        return any(
            any(marker in state for marker in ("tax", "exclude", "max", "tokensfromtax"))
            for state in self._normalized_states(report)
        )

    def _is_admin_full_balance_self_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_self_callback(report):
            return False
        if self._normalized_states(report) != {"contract_balance"}:
            return False
        expression = self._compact_expression(expression)
        if "address(this).balance" not in expression:
            return False
        return self._normalize(report.source_function) in {"avoidlocks", "close"}

    def _is_value_passthrough_self_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        return (
            self._is_classic_self_callback(report)
            and self._compact_expression(expression) == "target.call.value(msg.value)()"
        )

    def _is_drain_full_balance_self_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_self_callback(report):
            return False
        if self._normalize(report.source_function) != "drain":
            return False
        expression = self._compact_expression(expression)
        return "msg.sender.call.value(address(this).balance)" in expression

    def _is_unlock_token_holder_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_fallback(report):
            return False
        states = self._normalized_states(report)
        if not (states & {"holderlist", "lockbalance"}):
            return False
        expression = self._compact_expression(expression)
        return "transfer(msg.sender" in expression or "token.transfer(toaccount" in expression

    def _is_router_liquidity_bootstrap_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_fallback(report):
            return False
        states = self._normalized_states(report)
        if not (states & {"contract_balance", "pair", "_decimals", "_decimalsmul", "_status"}):
            return False
        expression = self._compact_expression(expression)
        if not any(marker in expression for marker in ("router.addliquidityeth", "dexrouter.addliquidityeth")):
            return False
        return "owner()" in expression or "liquidityaddress" in expression

    def _is_logevent_delegatecall_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_fallback(report):
            return False
        expression = self._compact_expression(expression)
        return "delegatecall" in expression and "logevent" in expression

    def _is_fixed_literal_distribution_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_self_callback(report):
            return False
        expression = self._compact_expression(expression)
        return expression.startswith("this.transfer(0x") or "sharestokenaddress.transfer(owner" in expression

    def _is_reentrancy_lock_cash_change_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_fallback(report):
            return False
        if self._normalized_states(report) != {"reentrancylock"}:
            return False
        return "msg.sender.call{value:cashchange}" in self._compact_expression(expression)

    def _is_multisig_m_txs_execution_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_fallback(report):
            return False
        if self._normalized_states(report) != {"m_txs"}:
            return False
        return "_to.call.value(_value)(_data)" in self._compact_expression(expression)

    def _is_business_lifecycle_callback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        if not self._is_classic_fallback(report):
            return False

        expression = self._compact_expression(expression)
        states = self._normalized_states(report)
        is_self_callback = self._is_classic_self_callback(report)

        if is_self_callback and states == {"holders"}:
            return "_addr.call.value(_wei)" in expression

        if is_self_callback and states == {"unlocked"}:
            return "wrapped_eth.deposit.value(balance)" in expression

        if "fee_recipient_" in expression and "call{value:fee}" in expression:
            return True

        if is_self_callback and states and states <= {"mintokensbeforeswap", "restrictionsenabled"}:
            return "_to.call{value:amount}" in expression

        if is_self_callback and states == {"states"}:
            return "attendees[i].call.value(reward)" in expression

        if states == {"tiertotal"}:
            return "token.transfer(beneficiary,tokens)" in expression

        if states == {"tokenstransferredtohold"}:
            return "token.transfer(holdcontract,tokenraised)" in expression

        if (
            is_self_callback
            and states & {"beneficiaries", "addresses", "totalreleased"}
            and (
                "token.transfer(owner,refund)" in expression
                or "token.transfer(owner,balance)" in expression
            )
        ):
            return True

        if (
            states & {"totaldividends", "totaldonated", "totaldonations", "currentholders"}
            and (
                "p3d.sell(tokens)" in expression
                or "p3d.buy.value(purchase)" in expression
            )
        ):
            return True

        if (
            states & {"_totalsupply", "pool", "_guardcounter"}
            and any(
                marker in expression
                for marker in (
                    "aave(getaave()).deposit",
                    "atoken(aavetoken).redeem",
                    "dydx(dydx).operate",
                    "compound(compound).mint",
                    "fulcrum(fulcrum).burn",
                )
            )
        ):
            return True

        if any(
            marker in expression
            for marker in (
                "kybernetworkproxy.swap",
                "rebalancingmodule.redeemrebalancingset",
                "ierc20(_fromtoken).transfer(address(tradeaccounting)",
            )
        ):
            return True

        if (
            states & {"totalcrldistributed", "totalvesting"}
            and "_crypteloerc20.transfer(_to,_amountcrl)" in expression
        ):
            return True

        if "supporterfee" in states and any(
            marker in expression
            for marker in (
                "ipool(_poollist[i]).paymenttoken()",
                "ipool(_pool).paymenttoken()",
                "ipool(_poollist[i]).swapftfornft",
            )
        ):
            return True

        if states == {"orders"}:
            return "monethagateway.acceptpayment.value(order.price)" in expression

        if "currentround" in states and "currentround" in expression:
            return True

        if states == {"users"}:
            return "users[msg.sender].touzizongshu" in expression

        if (
            states & {"_status", "vstats"}
            and "derpcontract.safetransferfrom(address(this),msg.sender,tokenid)" in expression
        ):
            return True

        if (
            is_self_callback
            and states == {"merchanthistory"}
            and "_merchanthistory.merchantidhash()==merchantidhash" in expression
        ):
            return True

        if states == {"withdrawablesusdfees"}:
            return "synthetix.issuesynths" in expression

        if states & {"amountraised", "resamount", "raisedether", "soldbeercoins"} and (
            "tokenreward.transfer(msg.sender" in expression
            or "beercoin.transfer(msg.sender" in expression
            or "beercoin.transfer(to," in expression
        ):
            return True

        if states == {"collectedfees"}:
            return "tokencontract.transferfrom" in expression

        if states == {"contract_balance"} and "msg.sender.call{value:(address(this).balance)}" in expression:
            source = self._normalize(report.source_function)
            return source.startswith(
                (
                    "team",
                    "importantfunction",
                    "policemanfunctions",
                    "enabletrade",
                    "launch",
                    "opentrading",
                )
            )

        if "lasttotalbalance" in states and any(
            marker in expression
            for marker in (
                "hourglass.sell",
                "refhandler.sendeth",
                "refhandler.buytokens",
                "hourglass.withdraw",
            )
        ):
            return True

        if "_reservedmints" in states:
            return "account.call{value:amount}" in expression

        if states & {"buyamount", "sellamount"}:
            return "dividendtracker.process(gas)" in expression

        if "tokenholdersmap.set(account,newbalance)" in expression:
            return True

        if any(
            marker in expression
            for marker in (
                "_itemids.increment()",
                "_itemssold.increment()",
                "_itemscancelled.increment()",
                "_offerids.increment()",
            )
        ):
            return True

        if "swaplist" in states and any(
            marker in expression
            for marker in (
                "erc20interface(nftstwo",
                "erc1155interface(nftstwo",
                "erc721interface(nftsone",
                "_swapids.increment()",
            )
        ):
            return True

        if "tokensselling" in states:
            return "token.transfer(beneficiary,tokensselling)" in expression

        if states and states <= {"deposits", "proposals"}:
            return "erc20interface(votingtokenaddr).transferfrom(msg.sender,this,amount)" in expression

        if states == {"_status"}:
            return "address(msg.sender).call{value:price}" in expression

        if "dividendtracker.excludefromdividends" in expression and (
            states & {"excludedfromdividends", "_owner"}
        ):
            return True

        if states == {"contract_balance"} and "msg.sender.call{value:(address(this).balance)}" in expression:
            source = self._normalize(report.source_function)
            return source.startswith(("removeblacklisted", "switchfunctions", "livefunctions"))

        if "isbot" in states and "ierc20(pair).transfer(team1_receiver" in expression:
            return True

        if "_allowances" in states and "address(mining_receiver).call{value:" in expression:
            return True

        if states == {"contract_balance"}:
            return "exchange.ethtotokenswapoutput.value(msg.value)(fee,block.timestamp)" in expression

        if states & {"swap", "token"} and any(
            marker in expression
            for marker in (
                "token.createtoken.value(msg.value)",
                "swap.createswap.value",
                "swap.enterswap",
                "token.transfer(_swapadd,msg.value)",
            )
        ):
            return True

        if (
            states & {"_totalsupply", "pool", "_guardcounter"}
            and "fulcrum(fulcrum).mint" in expression
        ):
            return True

        if states & {"etherinprogress", "etherrejected", "tokeninprogress", "pendingmints"} and any(
            marker in expression for marker in ("minter.unreserve", "minter.reserve", "minter.mintreserved")
        ):
            return True

        if (
            states & {"vestedtokens", "firstdeadline", "totalcrldistributed", "totalvesting"}
            and "_crypteloerc20.transfer(_to,_amountcrl)" in expression
        ):
            return True

        if "tokenbalanceledger_" in states and "mooninccontract.handleproduction" in expression:
            return True

        if states & {"order_book", "shitcoins", "etx_balances", "main_fee"} and (
            "shitcoin.transfer(make.owner" in expression
            or "shitcoin.transfer(take.owner" in expression
        ):
            return True

        return False

    def _is_classic_self_callback(self, report: VulnerabilityReport) -> bool:
        if not self._is_classic_fallback(report):
            return False
        source = self._normalize(report.source_function)
        target = self._normalize(report.target_function)
        callback = self._normalize((report.callback_entry or {}).get("function"))
        return bool(source) and (source == target or source == callback)

    def _has_status_state(self, report: VulnerabilityReport) -> bool:
        return "_status" in self._normalized_states(report)

    def _is_status_only(self, report: VulnerabilityReport) -> bool:
        return self._normalized_states(report) == {"_status"}

    def _is_marketplace_settlement_fallback(
        self, report: VulnerabilityReport, expression: str
    ) -> bool:
        target = self._normalize(report.target_function)
        return any(marker in target for marker in self.STRICT_MARKETPLACE_TARGET_MARKERS) and any(
            marker in expression for marker in self.STRICT_MARKETPLACE_RECEIVER_MARKERS
        )

    def _function_signature_text(self, report: VulnerabilityReport, function_name: object) -> str:
        normalized_function = self._normalize(function_name)
        if not normalized_function:
            return ""

        for node in report.evidence_path or []:
            if not isinstance(node, dict):
                continue
            if self._normalize(node.get("function")) != normalized_function:
                continue
            line_number = node.get("line")
            file_path = node.get("file")
            if not line_number or not file_path:
                continue
            signature = self._signature_near_line(file_path, normalized_function, int(line_number))
            if signature:
                return signature
        return ""

    def _signature_near_line(self, file_path: object, function_name: str, line_number: int) -> str:
        lines = self._source_lines(file_path)
        if not lines or line_number <= 0:
            return ""

        pattern = re.compile(r"\bfunction\s+" + re.escape(function_name) + r"\s*\(", re.IGNORECASE)
        start = max(0, line_number - 80)
        end = min(len(lines), line_number + 5)

        for index in range(start, end):
            if not pattern.search(lines[index]):
                continue
            parts: List[str] = []
            for sig_index in range(index, min(len(lines), index + 12)):
                line = lines[sig_index].split("//", 1)[0].strip()
                if line:
                    parts.append(line)
                if "{" in lines[sig_index] or ";" in lines[sig_index]:
                    break
            return self._normalize(" ".join(parts))
        return ""

    def _source_lines(self, file_path: object) -> List[str]:
        normalized_path = str(file_path or "").replace("/", "\\")
        if not normalized_path:
            return []
        if normalized_path not in self._source_cache:
            try:
                self._source_cache[normalized_path] = Path(normalized_path).read_text(
                    encoding="utf-8",
                    errors="ignore",
                ).splitlines()
            except OSError:
                self._source_cache[normalized_path] = []
        return self._source_cache[normalized_path]

    def _external_call_expression(self, report: VulnerabilityReport) -> str:
        external_call = report.external_call or {}
        return self._normalize(external_call.get("expression"))

    def _has_eth_value_transfer(self, expression: str) -> bool:
        return any(marker in expression for marker in self.ETH_VALUE_MARKERS)

    def _is_dynamic_low_level_call(self, expression: str) -> bool:
        return ".call" in expression and any(
            marker in expression for marker in self.DYNAMIC_LOW_LEVEL_MARKERS
        )

    def _is_pure_library_expression(self, expression: str) -> bool:
        if self._has_callback_capable_call(expression):
            return False
        if not any(marker in expression for marker in self.PURE_LIBRARY_MARKERS):
            return False

        call_names = set(self._call_names(expression))
        unknown_calls = call_names - self.PURE_LIBRARY_CALL_NAMES
        return not unknown_calls

    def _is_readonly_query_expression(self, expression: str) -> bool:
        if self._has_callback_capable_call(expression):
            return False

        call_names = self._call_names(expression)
        if not call_names:
            return False
        if any(
            any(hint in name for hint in self.STATE_CHANGING_CALL_HINTS)
            for name in call_names
        ):
            return False

        return all(
            name in self.READONLY_CALL_NAMES
            or name.endswith("address")
            or any(name.startswith(prefix) for prefix in self.READONLY_CALL_PREFIXES)
            for name in call_names
        )

    def _is_token_transfer_expression(
        self, report: VulnerabilityReport, states: set[str], expression: str
    ) -> bool:
        if "safetransfereth" in expression:
            return False
        has_token_transfer = any(marker in expression for marker in self.TOKEN_TRANSFER_MARKERS)
        if not has_token_transfer and ".transfer(" not in expression:
            return False
        if "msg.sender.transfer(" in expression or "tx.origin.transfer(" in expression:
            return False
        if not (has_token_transfer or any(marker in expression for marker in self.TOKEN_OBJECT_MARKERS)):
            return False

        bookkeeping_states = (
            self.TOKEN_BOOKKEEPING_STATES
            | self.REWARD_BOOKKEEPING_STATES
            | self.LOCK_BOOKKEEPING_STATES
            | self.POOL_BOOKKEEPING_STATES
            | {"isreleased"}
        )
        if states & bookkeeping_states:
            return True

        source = self._normalize(report.source_function)
        target = self._normalize(report.target_function)
        return source in self.TOKEN_FUNCTIONS and target in self.TOKEN_FUNCTIONS

    def _has_callback_capable_call(self, expression: str) -> bool:
        if self._has_eth_value_transfer(expression) or self._is_dynamic_low_level_call(expression):
            return True
        return "safetransfereth" in expression or "sendvalue" in expression or "transfereth" in expression

    def _call_names(self, expression: str) -> List[str]:
        names: List[str] = []
        token = ""
        previous = ""

        for char in expression:
            if char.isalnum() or char == "_":
                token += char
                continue
            if char == "(" and previous == "." and token:
                names.append(token.lower())
            previous = char
            token = ""

        return names

    def _normalized_states(self, report: VulnerabilityReport) -> set[str]:
        return {self._normalize(state) for state in report.key_states if state}

    def _normalize(self, value: object) -> str:
        return str(value or "").strip().lower()

    def _compact_expression(self, expression: object) -> str:
        return "".join(str(expression or "").lower().split())
