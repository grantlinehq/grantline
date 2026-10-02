import type { Source } from "../types";

export function sourceCollectionMessage(source: Source): string {
  if (source.complete) return "Selected scope collected";
  if (source.error_code === "HTTP_401")
    return "Credentials expired or rejected. Renew access and collect again.";
  if (source.error_code === "HTTP_403")
    return "Access denied. Review the source permissions and scope.";
  return "Collection incomplete. Review source access and scope.";
}
