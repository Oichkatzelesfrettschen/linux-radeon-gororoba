# R3V Vulkan normative source references

The API registry inventories commands and types. The prose specification defines
the memory and synchronization obligations that cross the R3V and DRM boundary.
`policy/r3v-vulkan-drm-requirements.json` retains selected exact excerpts from
Khronos Vulkan-Docs commit `ab08f0951ef1ad9b84db93f971e113c1d9d55609`.
The registry pins Mesa and kernel source baselines separately from later repairs.

## Offline reproduction

The caller supplies an existing Vulkan-Docs checkout or bare Git cache containing
the pinned commit. Its upstream is
<https://github.com/KhronosGroup/Vulkan-Docs>.
Source acquisition occurs separately from validation. The checker reads Git
objects and emits its verdict to standard output.

```sh
"$PYTHON" -W error scripts/check_r3v_drm_requirement_sources.py \
  --mesa-tree "$MESA_TREE" --vulkan-tree "$VULKAN_TREE" --selftest
"$PYTHON" -O -W error scripts/check_r3v_drm_requirement_sources.py \
  --mesa-tree "$MESA_TREE" --vulkan-tree "$VULKAN_TREE" --selftest
ruff check scripts/check_r3v_drm_requirement_sources.py
```

`$PYTHON` names the caller-selected interpreter. `CHAPTER_BLOBS` pins the Git
blob identity of each chapter under `doc/specs/vulkan/chapters/`. The checker
accepts standalone and bullet-form anchor declarations. An excerpt matches
literal source text after its anchor and before the next declaration. A
cross-reference to an anchor supplies neither a declaration nor an excerpt.

## Evidence boundary

The twenty-one excerpts cover allocation parameters, alignment and size failure,
the coherent memory-type minimum and cache semantics, buffer and image binding
size, alignment and memory types, memory dependency ordering,
availability and visibility, access scopes, queue fence scope, and finite waits
after device loss. Terminal logical-device loss and object lifetime have separate
supporting clauses. The lost-device wait excerpt preserves the swapchain
conditional directives so extension scope remains explicit.

The excerpt check establishes source identity and location. Schema version 2
requires the declared supporting-claim inventory and rejects duplicate or missing
claims and requirements. Human review still determines whether a quotation
supports each interpretation. Packet admission and suspend require additional
mappings. The tracker keeps
behavioral tests at `not_run`; parser execution and retained target observations
remain separate evidence in `steinmarder-r300`.

A signaled fence and a visible payload answer different questions. Fence scope
orders operations; availability and visibility govern the values that consumers
can access. Qualification tests record ordering and directional payload checks
separately.

R3V owns image layout and translates binding offsets into packet addresses.
The kernel parser validates those addresses against GEM objects. Application
valid-usage rules and kernel containment therefore have separate negative
controls. Likewise, TTM placement policy and advertised Vulkan memory properties
name different contracts; a placement retry alone establishes a policy choice,
while a property violation needs an observable failure of the advertised behavior.
