import { useEffect, useRef } from "react";

const GAP = 22; // px between grid cells
const RADIUS = 170; // cursor influence radius
const RGB = "52, 211, 153"; // emerald-400, same as the logo

/** Background grid of pixel dots that twinkle and light up / push away around the cursor. */
export default function PixelField() {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current!;
    const ctx = canvas.getContext("2d")!;
    const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
    let w = 0, h = 0, raf = 0;
    const target = { x: -1e4, y: -1e4 };
    const cur = { x: -1e4, y: -1e4, k: 0 }; // eased cursor + its strength (fades on leave)
    let inside = false;

    const resize = () => {
      const dpr = devicePixelRatio || 1;
      ({ width: w, height: h } = canvas.getBoundingClientRect());
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      if (still) draw(0);
    };

    function draw(t: number) {
      ctx.clearRect(0, 0, w, h);
      const ease = still ? 1 : 0.18; // reduced motion: no glide, just follow
      cur.x += (target.x - cur.x) * ease;
      cur.y += (target.y - cur.y) * ease;
      cur.k += ((inside ? 1 : 0) - cur.k) * (still ? 1 : 0.08);
      const ox = (w % GAP) / 2, oy = (h % GAP) / 2;
      for (let gx = 0; gx * GAP < w; gx++) {
        for (let gy = 0; gy * GAP < h; gy++) {
          let x = ox + gx * GAP, y = oy + gy * GAP;
          const phase = ((gx * 73856093) ^ (gy * 19349663)) % 628 / 100; // stable per-cell offset
          let a = 0.05 + (still ? 0 : 0.035 * (Math.sin(t / 900 + phase) + 1));
          let s = 2;
          const dx = x - cur.x, dy = y - cur.y, d = Math.hypot(dx, dy);
          if (d < RADIUS && cur.k > 0.01) {
            const f = (1 - d / RADIUS) ** 2 * cur.k;
            a += f * 0.75;
            s += f * 2.5;
            x += (dx / (d || 1)) * f * 7; // push away from the cursor
            y += (dy / (d || 1)) * f * 7;
          }
          ctx.fillStyle = `rgba(${RGB}, ${a})`;
          ctx.fillRect(Math.round(x - s / 2), Math.round(y - s / 2), Math.round(s), Math.round(s));
        }
      }
    }

    const loop = (t: number) => {
      draw(t);
      raf = requestAnimationFrame(loop);
    };
    const move = (e: PointerEvent) => {
      const r = canvas.getBoundingClientRect();
      target.x = e.clientX - r.left;
      target.y = e.clientY - r.top;
      inside = target.x >= 0 && target.y >= 0 && target.x <= r.width && target.y <= r.height;
      if (cur.k < 0.01) Object.assign(cur, { x: target.x, y: target.y }); // no glide in from far away
      if (still) draw(0);
    };
    const leave = () => {
      inside = false;
      if (still) draw(0);
    };

    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    addEventListener("pointermove", move);
    document.addEventListener("pointerleave", leave);
    if (!still) raf = requestAnimationFrame(loop);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      removeEventListener("pointermove", move);
      document.removeEventListener("pointerleave", leave);
    };
  }, []);

  return (
    <canvas
      ref={ref}
      aria-hidden
      className="pointer-events-none absolute inset-0 size-full [mask-image:radial-gradient(ellipse_at_center,black_35%,transparent_85%)]"
    />
  );
}
