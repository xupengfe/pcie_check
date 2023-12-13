#!/bin/bash

readonly DVSEC_INFO="Designated Vendor-Specific"
readonly CXL_LIST_FILE="/tmp/cxl_list.log"
readonly CXL3_LIST_FILE="/tmp/cxl3_list.log"

find_cxl_pcie() {
  local pcie_list=""
  local pcie=""
  local is_cxl=""
  local is_cxl3=""

  [[ -e "$CXL_LIST_FILE" ]] && mv "$CXL_LIST_FILE" "${CXL_LIST_FILE}_old"
  [[ -e "$CXL3_LIST_FILE" ]] && mv "$CXL3_LIST_FILE" "${CXL3_LIST_FILE}_old"
  cat /dev/null > "$CXL_LIST_FILE"
  cat /dev/null > "$CXL3_LIST_FILE"
  pcie_list=$(lspci -v | grep -B 50 "Vendor-Specific" | grep "^0" | cut -d " " -f 1)

  for pcie in $pcie_list; do
    is_cxl=$(lspci -v -s "$pcie" | grep -i "$DVSEC_INFO")
    if [[ -z "$is_cxl" ]]; then
      continue
    else
      echo "$pcie" >> "$CXL_LIST_FILE"
    fi
    is_cxl3=$(lspci -v -s "$pcie" | grep -i "$DVSEC_INFO" | grep -i "Rev=2")
    if [[ -n "$is_cxl3" ]]; then
      echo "$pcie" >> "$CXL3_LIST_FILE"
    fi
  done

  echo "CXL PCIe list in $CXL_LIST_FILE:"
  cat "$CXL_LIST_FILE"
  echo "------------------"
  echo "CXL3.0 PCIe list in $CXL3_LIST_FILE:"
  cat "$CXL3_LIST_FILE"
}

find_cxl_pcie
