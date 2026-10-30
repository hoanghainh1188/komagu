# Disaster Recovery (DR) & Failover Runbook (Boilerplate 3)
## ディザスタリカバリ（DR）および広域災害復旧手順書

- **System**: Multi-Region Infrastructure & Immutable Backup Architecture
- **Primary Region**: Tokyo (`ap-northeast-1`)
- **Secondary / DR Region**: Osaka (`ap-northeast-3`)
- **Target RTO (Recovery Time Objective)**: < 15 minutes
- **Target RPO (Recovery Point Objective)**: < 60 minutes
- **Compliance Standard**: S3 Object Lock (Compliance Mode WORM)

> [!NOTE]
> RTO and RPO metrics reported by `DRManager.execute_failover_restore()` are simulated synthetic benchmarks designed to validate automated orchestration logic without incurring multi-gigabyte data transfer overhead during automated testing.

---

## 1. Trigger Criteria for Disaster Declaration (発災・切替判断基準)

A Disaster Recovery failover is declared by the Incident Commander / Principal Architect (Harry) when one of the following criteria is met:
1. **Regional Outage**: Total failure of AWS Tokyo region (`ap-northeast-1`) lasting longer than 15 minutes.
2. **Ransomware / Hostile Compromise**: Mass encryption or destructive deletion on primary data stores (analogous to the IDC Frontier October 2026 incident).
3. **Severe Data Corruption**: Irreversible database mutation where primary replicas are corrupted.

---

## 2. Recovery Procedures (復旧フェーズ別手順)

### Phase 1: Isolation & Triage (隔離・初期調査)
1. **Sever Primary Traffic**: Direct DNS / Route53 away from Tokyo Application Load Balancer to a static holding page or directly to Osaka DR endpoints.
2. **Verify Backup Integrity**:
   ```bash
   python3 -c "from remediate.resilience.dr.dr_manager import DRManager; mgr = DRManager(); print(mgr.verify_integrity('snapshot-latest'))"
   ```

### Phase 2: Secondary Cluster Activation (大阪スタンバイ環境起動)
1. Scale Osaka ECS tasks from 0 (warm standby) to production capacity:
   ```bash
   aws ecs update-service --cluster komagu-production-standby-dr-cluster \
     --service api-gateway --desired-count 4 --region ap-northeast-3
   ```
2. Rehydrate relational state from S3 Object Lock Compliance WORM bucket:
   ```bash
   python3 -m remediate.resilience.dr.dr_manager --restore --snapshot-id "latest-verified"
   ```

### Phase 3: Route53 Traffic Cutover (DNS切替)
1. Update DNS failover record to point to Osaka ALB (`osaka-dr-alb.komagu.internal`).
2. Verify smoke test health check returns HTTP 200 on all core endpoints.

---

## 3. Post-Recovery & Fallback Verification (復旧後検証)

- Confirm Zero Data Loss against S3 WORM integrity logs.
- Audit retention policies to verify that the compliance lock remains uncompromised.
