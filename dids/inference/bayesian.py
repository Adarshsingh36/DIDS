"""
Bayesian Inference Engine — The "thinking" component.

This file contains the mathematical brain of the system. It uses a statistical technique
called "Bayesian reasoning" to figure out what type of attack is most likely happening.

Think of it like a doctor:
- Doctor sees symptoms (events): fever, cough, sore throat
- Doctor knows: "Fever + cough usually means flu" (probability)
- Doctor calculates: What disease best explains these symptoms?
- Doctor's conclusion: "Probably flu (80%), could be cold (15%)"

Similarly, this engine:
- Sees events (failed_login, repeated_auth_failure, etc)
- Knows: "Failed logins usually mean brute force attack"  
- Calculates: Which attack type best explains what we saw?
- Returns: "Probably brute force (80%), could be other (20%)"

The engine supports both single-agent reasoning (one agent's beliefs) and
multi-agent aggregation (combining beliefs from many agents).
"""

from __future__ import annotations
import math
import logging
from typing import Dict, List, Sequence

from dids.core.models import AttackType, BeliefVector, SecurityEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Knowledge Base - Probabilities that connect events to attack types
# ---------------------------------------------------------------------------
"""
This is a lookup table: given an event type, what's the probability it came
from each type of attack?

Example: "failed_login" event
  - Usually means brute force (90% probability)
  - Might mean privilege escalation (30% probability)  
  - Unlikely to mean DDoS (2% probability)

These percentages are "hand-tuned" - a real system would learn from data.
"""
_LIKELIHOOD: Dict[str, Dict[str, float]] = {
    # event_type  ->  { attack_type -> P(event | attack) }
    "failed_login":          {
        AttackType.BRUTE_FORCE.value:     0.90,
        AttackType.PORT_SCAN.value:       0.05,
        AttackType.DDOS.value:            0.02,
        AttackType.PRIVILEGE_ESCAL.value: 0.30,
        AttackType.DATA_EXFIL.value:      0.05,
        AttackType.MALWARE.value:         0.10,
    },
    "repeated_auth_failure":  {
        AttackType.BRUTE_FORCE.value:     0.95,
        AttackType.PRIVILEGE_ESCAL.value: 0.40,
        AttackType.MALWARE.value:         0.15,
    },
    "port_scan_detected":    {
        AttackType.PORT_SCAN.value:       0.92,
        AttackType.DDOS.value:            0.20,
        AttackType.DATA_EXFIL.value:      0.15,
    },
    "high_traffic_volume":   {
        AttackType.DDOS.value:            0.88,
        AttackType.PORT_SCAN.value:       0.30,
        AttackType.DATA_EXFIL.value:      0.20,
    },
    "privilege_escalation":  {
        AttackType.PRIVILEGE_ESCAL.value: 0.93,
        AttackType.MALWARE.value:         0.40,
    },
    "unusual_file_access":   {
        AttackType.DATA_EXFIL.value:      0.80,
        AttackType.MALWARE.value:         0.55,
        AttackType.PRIVILEGE_ESCAL.value: 0.30,
    },
    "suspicious_process":    {
        AttackType.MALWARE.value:         0.85,
        AttackType.PRIVILEGE_ESCAL.value: 0.35,
    },
    "outbound_data_spike":   {
        AttackType.DATA_EXFIL.value:      0.88,
        AttackType.DDOS.value:            0.20,
    },
    "icmp_flood":            {
        AttackType.DDOS.value:            0.90,
    },
    "syn_flood":             {
        AttackType.DDOS.value:            0.92,
    },
}

# Starting assumption: equal probability for all attack types
_ATTACK_TYPES = [a.value for a in AttackType if a != AttackType.UNKNOWN]
_UNIFORM_PRIOR: Dict[str, float] = {a: 1.0 / len(_ATTACK_TYPES) for a in _ATTACK_TYPES}


class BayesianInferenceEngine:
    """
    Local Bayesian reasoner for calculating attack probabilities.
    
    This engine takes a sequence of security events and calculates:
    "Which attack type best explains what we're seeing?"
    
    The core idea (Bayes' Theorem in plain English):
    - Start with a prior belief (all attacks equally likely)
    - For each new event, update belief proportionally to how well
      the event matches that attack type
    - Result: posterior belief (revised opinion after seeing evidence)
    """

    def __init__(self, decay: float = 0.95) -> None:
        """
        Parameters
        ----------
        decay : Decay factor for old beliefs
                0.95 = beliefs "age" - older evidence becomes less important
                This models: "Recent events matter more than old ones"
        """
        self._decay = decay

    # ------------------------------------------------------------------
    # Public API - Main reasoning methods
    # ------------------------------------------------------------------

    def compute_belief(self, events: Sequence[SecurityEvent],
                       prior: Dict[str, float] | None = None) -> Dict[str, float]:
        """
        Given security events, calculate probability of each attack type.
        
        Process (simplified):
        1. Start with prior beliefs (P(attack_type) before seeing events)
        2. For each event, say "how likely is this event if attack_type is true?"
        3. Multiply all these likelihoods together for each attack type
        4. Normalize so probabilities sum to 1.0
        
        Result: Dictionary mapping attack_type -> probability
        
        Example input:
          - Event 1: failed_login from 192.168.1.100
          - Event 2: repeated_auth_failure
          - Event 3: another failed_login
        
        Example output:
          - brute_force: 0.85
          - malware: 0.10
          - other: 0.05
        """
        # Use log-space to avoid numerical problems with very small numbers
        log_posterior = {
            a: math.log(p + 1e-12)  # Start with prior belief in log space
            for a, p in (prior or _UNIFORM_PRIOR).items()
        }

        # For each event, update our beliefs
        for event in events:
            # Get the likelihoods for this event type
            likelihoods = _LIKELIHOOD.get(event.event_type, {})
            
            # Update each attack type's belief based on this event
            for attack in _ATTACK_TYPES:
                p_ev_given_atk = likelihoods.get(attack, 0.01)  # Default likelihood
                log_posterior[attack] += math.log(p_ev_given_atk)

        # Convert back from log space to probabilities
        max_log = max(log_posterior.values())  # Prevent overflow
        unnorm = {a: math.exp(v - max_log) for a, v in log_posterior.items()}
        total = sum(unnorm.values())
        return {a: v / total for a, v in unnorm.items()}

    def update_belief_vector(self, bv: BeliefVector,
                             new_events: Sequence[SecurityEvent]) -> BeliefVector:
        """
        Update an existing belief vector with new events.
        
        This incorporates:
        1. Old beliefs (with decay - they age)
        2. New events (recompute updated beliefs)
        
        Returns a fresh BeliefVector with updated probabilities and timestamp.
        """
        # Decay old beliefs (1 year old events = less important)
        decayed_prior = {k: v * self._decay for k, v in bv.beliefs.items()} \
                        if bv.beliefs else None
        # Compute new beliefs using decayed prior
        new_beliefs = self.compute_belief(new_events, prior=decayed_prior)
        import time
        return BeliefVector(origin_id=bv.origin_id,
                            timestamp=time.time(),
                            beliefs=new_beliefs)

    # ------------------------------------------------------------------
    # Multi-agent aggregation - Combining beliefs from multiple sources
    # ------------------------------------------------------------------

    @staticmethod
    def aggregate_beliefs(belief_vectors: List[BeliefVector]) -> Dict[str, float]:
        """
        Combine beliefs from multiple agents into one consensus belief.
        
        Why? Because:
        - One agent might see "port scans" (thinks port scan attack)
        - Another agent might see "high traffic" (thinks DDoS attack)
        - Both are probably seeing the SAME attack
        
        This method combines them: "Most likely a DDoS with some recon"
        
        Method: Geometric mean of probabilities
        (Like averaging opinions, but mathematically careful)
        """
        if not belief_vectors:
            return {}

        # Collect all attack types mentioned by any agent
        all_attacks = set()
        for bv in belief_vectors:
            all_attacks.update(bv.beliefs.keys())

        # Compute geometric mean in log space
        log_sum: Dict[str, float] = {a: 0.0 for a in all_attacks}
        for bv in belief_vectors:
            for attack in all_attacks:
                p = bv.beliefs.get(attack, 1e-12)  # Default if not mentioned
                log_sum[attack] += math.log(p)

        # Convert back to probabilities
        n = len(belief_vectors)
        raw = {a: math.exp(v / n) for a, v in log_sum.items()}
        total = sum(raw.values())
        if total == 0:
            return {}
        return {a: v / total for a, v in raw.items()}
