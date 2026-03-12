# Paper Directory

This directory contains the working LaTeX manuscript for the OpenClaw PRISM paper.

## Files

- `main.tex` - top-level manuscript file
- `sections/` - section-level LaTeX source
- `references.bib` - current bibliography used by the manuscript
- `generated/` - optional generated LaTeX fragments used during result promotion

## Result Promotion Workflow

Final evaluation rows should be promoted into `paper/generated/` only from a
publication-ready benchmark artifact, not from the current preliminary runs.
The helper scripts for that workflow live at:

- [promote-paper-results.ts](/C:/Users/kyaky/Documents/Playground/openclaw-prism/evaluation/promote-paper-results.ts)

The expected upstream packaging step for benchmark artifacts lives at:

- [package-paper-artifact.ts](/C:/Users/kyaky/Documents/Playground/openclaw-prism/evaluation/package-paper-artifact.ts)
- [build-benchmark-artifact.ts](/C:/Users/kyaky/Documents/Playground/openclaw-prism/evaluation/build-benchmark-artifact.ts)
- [finalize-paper-main-results.ts](/C:/Users/kyaky/Documents/Playground/openclaw-prism/evaluation/finalize-paper-main-results.ts)

## Current Status

- The manuscript body is assembled and compiles to `main.pdf`.
- Sections 1 through 8 are present in LaTeX and wired into `main.tex`.
- Core figures, bibliography entries, and preliminary evaluation tables are in place.
- The paper body no longer depends on visible placeholder tables.
- The remaining major gap is a publication-ready end-to-end main-results artifact.

## Next Steps

1. Finalize a publication-ready end-to-end benchmark artifact.
2. Promote final main-result rows into `paper/generated/` from that artifact.
3. Re-run a full LaTeX compile and review page layout, captions, and bibliography formatting.
4. Freeze the paper-facing artifact version before any arXiv upload.
