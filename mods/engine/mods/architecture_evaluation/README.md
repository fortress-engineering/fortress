# Architecture Evaluation Module

This Module owns the declared component graph and architecture dependency
evaluation. Components have stable IDs, zones, exclusively owned paths, and
explicit dependencies. Architectural cycles are forbidden by default because
they obscure ownership and impact; an inseparable cluster should normally be
one component.

The declared graph is distinct from observed source dependencies. Future source
extraction may reconcile the two, but dependencies do not imply containment and
Module placement follows responsibility scope rather than import convenience.
