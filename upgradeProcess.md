# Upgrade and Cutover Plan

This document outlines the recommended upgrade and cutover steps for the Delivery Controllers (DDCs), StoreFront servers, and Virtual Delivery Agents (VDAs). Each phase is sequenced to reduce risk and ensure service continuity.  

---

## Delivery Controller (DDC) Upgrade Steps

1. **Upgrade Secondary DDC**  
   - Perform the binary upgrade on the secondary DDC.  
   - Use the **2402 installation ISO** and follow the `autorun` GUI to ensure all prerequisites are handled by the installer logic.  
   - Any VDAs registered to this DDC will automatically reconnect to the primary DDC (this may not occur immediately).  
   - After the binary upgrade, the secondary DDC will detect a schema mismatch and place itself in an inactive state.  

2. **Upgrade SQL Express**  
   - Verify that a SQL database backup exists prior to the upgrade.  
   - Upgrade SQL Express to **SQL Express 2022** using the binaries included on the 2402 installation ISO.  
   - Expect temporary SQL connectivity loss during this process.  

3. **Upgrade Primary DDC**  
   - Perform the binary upgrade on the primary DDC.  
   - A full outage will occur at this stage until the remaining steps are completed.  
   - Update the CVAD Site SQL schema using **Site Manager**.  
   - If Citrix Studio does not display properly after the schema update, re-run the schema update.  
   - After a successful schema update, verify that both DDCs have come back online.  

---

## StoreFront Upgrade Steps

1. Install **.NET Framework 4.7.2** using the **offline** installer.  
   - The installer included with the StoreFront binaries is a shim that requires external internet connectivity.  
2. Upgrade StoreFront binaries on the secondary server.  
3. Upgrade StoreFront binaries on the primary server.  

---

## VDA Upgrade Steps

1. Drain users from a single VDA instance through session attrition.  
2. Once all users are removed, upgrade the VDA binaries.
    - Several reboots may be required depending on the destination OS
3. Verify that the VDA successfully registers with the DDCs.  
4. Repeat the process until all VDAs in the site have been upgraded.  

---