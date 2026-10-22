import type { ComponentType, SVGProps } from "react";
import { Gear, User } from "pixelarticons/react";
import { AGENTS, type AgentName } from "./store";

export type IconType = ComponentType<SVGProps<SVGSVGElement>>;

// Pixel icons: crispEdges keeps the 24px grid sharp at any size.
export function Px({ icon: Icon, size = 16, className = "" }: { icon: IconType; size?: number; className?: string }) {
  return <Icon width={size} height={size} shapeRendering="crispEdges" aria-hidden className={`shrink-0 ${className}`} />;
}

export function AgentAvatar({ name, size = 24 }: { name: string; size?: number }) {
  const agent = AGENTS[name as AgentName];
  const icon = agent?.icon ?? (name === "user" ? User : Gear);
  return (
    <span className={`grid shrink-0 place-items-center rounded-md ${agent?.color ?? "bg-white/10 text-muted"}`} style={{ width: size, height: size }}>
      <Px icon={icon} size={Math.round(size * 0.62)} />
    </span>
  );
}
