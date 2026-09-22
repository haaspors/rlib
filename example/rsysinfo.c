#include <rlib/ros.h>

static const rchar *
_fmt_bytes (rchar * buf, rsize size, rsize bytes)
{
  static const rchar * unit[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB" };
  ruint64 whole = bytes, frac = 0;
  rsize i = 0;

  while (whole >= 1024 && i + 1 < R_N_ELEMENTS (unit)) {
    frac = ((whole % 1024) * 10) / 1024;
    whole /= 1024;
    i++;
  }

  if (i == 0)
    r_snprintf (buf, size, "%"RUINT64_FMT" %s", whole, unit[i]);
  else
    r_snprintf (buf, size, "%"RUINT64_FMT".%"RUINT64_FMT" %s", whole, frac,
        unit[i]);

  return buf;
}

static const rchar *
_cache_type_str (RSysCpuCacheType type)
{
  switch (type) {
    case R_SYS_CPU_CACHE_DATA:        return "data";
    case R_SYS_CPU_CACHE_INSTRUCTION: return "instruction";
    case R_SYS_CPU_CACHE_TRACE:       return "trace";
    default:                          return "unified";
  }
}


/* ----- JSON output ------------------------------------------------- */

/* The container mutators take a reference of their own. */
static void
_json_add (RJsonValue * obj, const rchar * name, RJsonValue * value)
{
  RJsonValue * key;

  if (value == NULL)
    return;

  /* Field names are literals, so the key can borrow. */
  if ((key = r_json_string_new_static_unescaped (name)) != NULL) {
    r_json_object_add_field (obj, key, value);
    r_json_value_unref (key);
  }
  r_json_value_unref (value);
}

static void
_json_add_num (RJsonValue * obj, const rchar * name, ruint64 value)
{
  _json_add (obj, name, r_json_number_new_double ((rdouble)value));
}

/* null keeps "not reported" apart from a genuine zero. */
static void
_json_add_num_or_null (RJsonValue * obj, const rchar * name, ruint64 value,
    ruint64 unknown)
{
  if (value == unknown)
    _json_add (obj, name, r_json_null_new ());
  else
    _json_add_num (obj, name, value);
}

static void
_json_add_str (RJsonValue * obj, const rchar * name, const rchar * value)
{
  _json_add (obj, name, r_json_string_new (value, -1, NULL));
}

static void
_json_add_bool (RJsonValue * obj, const rchar * name, rboolean value)
{
  _json_add (obj, name, value ? r_json_true_new () : r_json_false_new ());
}

static void
_json_append (RJsonValue * array, RJsonValue * value)
{
  if (value != NULL) {
    r_json_array_add_value (array, value);
    r_json_value_unref (value);
  }
}

static void
_json_add_bitset (RJsonValue * obj, const rchar * name, const RBitset * bitset)
{
  rchar * str = r_bitset_to_human_readable (bitset);

  _json_add_str (obj, name, str != NULL ? str : "");
  r_free (str);
}

static void
_json_add_cpuset (RJsonValue * obj, const rchar * name,
    rboolean (*fill) (RBitset * cpuset))
{
  RBitset * cpuset;

  if (r_bitset_init_stack (cpuset, r_sys_cpuset_max ()) && fill (cpuset))
    _json_add_bitset (obj, name, cpuset);
  else
    _json_add (obj, name, r_json_null_new ());
}

static RJsonValue *
_json_counts (void)
{
  RJsonValue * cpu, * sets;

  if ((cpu = r_json_object_new ()) == NULL)
    return NULL;

  _json_add_num (cpu, "packages", r_sys_cpu_packages ());
  _json_add_num (cpu, "physical_cores", r_sys_cpu_physical_count ());
  _json_add_num (cpu, "logical_cpus", r_sys_cpu_logical_count ());
  _json_add_num (cpu, "allowed_cpus", r_sys_cpu_allowed_count ());
  _json_add_num (cpu, "max_cpus", r_sys_cpu_max_count ());

  if ((sets = r_json_object_new ()) != NULL) {
    _json_add_cpuset (sets, "possible", r_sys_cpuset_possible);
    _json_add_cpuset (sets, "present", r_sys_cpuset_present);
    _json_add_cpuset (sets, "online", r_sys_cpuset_online);
    _json_add_cpuset (sets, "allowed", r_sys_cpuset_allowed);
    _json_add (cpu, "cpusets", sets);
  }

  return cpu;
}

static RJsonValue *
_json_numa (void)
{
  RJsonValue * numa;

  if ((numa = r_json_object_new ()) == NULL)
    return NULL;

  _json_add_num (numa, "nodes", r_sys_node_count ());
  _json_add_num (numa, "nodes_with_online_cpus",
      r_sys_node_count_with_online_cpus ());
  _json_add_num (numa, "nodes_with_allowed_cpus",
      r_sys_node_count_with_allowed_cpus ());
  _json_add_bool (numa, "placement_enforced", r_mem_numa_available ());
  _json_add_num (numa, "page_size", r_mem_numa_page_size ());

  return numa;
}

static RJsonValue *
_json_cpu (RSysCpu * cpu)
{
  RJsonValue * ret, * caches;
  RBitset * cpuset;
  rsize i, count;

  if (!r_bitset_init_stack (cpuset, r_sys_cpuset_max ()))
    return NULL;
  if ((ret = r_json_object_new ()) == NULL)
    return NULL;

  _json_add_num (ret, "id", r_sys_topology_cpu_id (cpu));
  _json_add_num_or_null (ret, "node", r_sys_topology_cpu_node_id (cpu),
      R_SYS_ID_UNKNOWN);
  _json_add_num_or_null (ret, "core", r_sys_topology_cpu_core_id (cpu),
      R_SYS_ID_UNKNOWN);
  _json_add_num_or_null (ret, "package", r_sys_topology_cpu_package_id (cpu),
      R_SYS_ID_UNKNOWN);
  _json_add_num_or_null (ret, "min_frequency_khz",
      r_sys_topology_cpu_min_frequency (cpu), 0);
  _json_add_num_or_null (ret, "max_frequency_khz",
      r_sys_topology_cpu_max_frequency (cpu), 0);

  if (r_sys_topology_cpu_siblings (cpu, cpuset))
    _json_add_bitset (ret, "siblings", cpuset);

  if ((caches = r_json_array_new ()) == NULL)
    return ret;

  for (i = 0, count = r_sys_topology_cpu_cache_count (cpu); i < count; i++) {
    RSysCpuCache cache;
    RJsonValue * entry;

    if (!r_sys_topology_cpu_cache (cpu, i, &cache))
      continue;
    if ((entry = r_json_object_new ()) == NULL)
      break;

    _json_add_num (entry, "level", cache.level);
    _json_add_str (entry, "type", _cache_type_str (cache.type));
    _json_add_num_or_null (entry, "size", cache.size, 0);
    _json_add_num_or_null (entry, "line_size", cache.linesize, 0);
    _json_add_num_or_null (entry, "ways", cache.ways, 0);
    _json_add_num_or_null (entry, "sets", cache.sets, 0);

    r_bitset_clear (cpuset);
    if (r_sys_topology_cpu_cache_cpuset (cpu, i, cpuset))
      _json_add_bitset (entry, "shared", cpuset);

    _json_append (caches, entry);
  }
  _json_add (ret, "caches", caches);

  return ret;
}

static RJsonValue *
_json_node_allocation (rsize id)
{
  RJsonValue * ret;
  rsize size = r_mem_numa_page_size ();
  ruint8 * mem;
  ruint got;

  if ((ret = r_json_object_new ()) == NULL)
    return NULL;

  _json_add_num (ret, "requested_node", id);
  if ((mem = r_mem_numa_alloc_onnode (size, (ruint)id)) == NULL) {
    _json_add_bool (ret, "allocated", FALSE);
    return ret;
  }

  _json_add_bool (ret, "allocated", TRUE);
  mem[0] = 1;
  if (r_mem_numa_node_of (mem, &got))
    _json_add_num (ret, "backing_node", got);
  else
    _json_add (ret, "backing_node", r_json_null_new ());

  r_mem_numa_free (mem, size);

  return ret;
}

static RJsonValue *
_json_node (RSysTopology * topo, RSysNode * node, rsize nodes)
{
  RJsonValue * ret, * distances, * cpus;
  RBitset * cpuset;
  rsize j, id, cpucount;

  if ((ret = r_json_object_new ()) == NULL)
    return NULL;

  id = r_sys_topology_node_id (node);
  cpucount = r_sys_topology_node_cpu_count (node);

  _json_add_num (ret, "id", id);
  _json_add_num_or_null (ret, "total_memory",
      r_sys_topology_node_total_memory (node), 0);
  _json_add_num_or_null (ret, "available_memory",
      r_sys_topology_node_available_memory (node), 0);

  if (r_bitset_init_stack (cpuset, r_sys_cpuset_max ()) &&
      r_sys_topology_node_cpuset (node, cpuset))
    _json_add_bitset (ret, "cpuset", cpuset);

  if ((distances = r_json_array_new ()) != NULL) {
    for (j = 0; j < nodes; j++) {
      RSysNode * other = r_sys_topology_node (topo, j);
      RJsonValue * entry;

      if (other == NULL)
        continue;
      if ((entry = r_json_object_new ()) != NULL) {
        rsize otherid = r_sys_topology_node_id (other);

        _json_add_num (entry, "node", otherid);
        _json_add_num_or_null (entry, "distance",
            r_sys_topology_node_distance (node, otherid), 0);
        _json_append (distances, entry);
      }
      r_sys_node_unref (other);
    }
    _json_add (ret, "distances", distances);
  }

  _json_add (ret, "allocation", _json_node_allocation (id));

  if ((cpus = r_json_array_new ()) != NULL) {
    for (j = 0; j < cpucount; j++) {
      RSysCpu * cpu = r_sys_topology_node_cpu (node, j);

      if (cpu != NULL) {
        _json_append (cpus, _json_cpu (cpu));
        r_sys_cpu_unref (cpu);
      }
    }
    _json_add (ret, "cpus", cpus);
  }

  return ret;
}

static RJsonValue *
_json_topology (void)
{
  RSysTopology * topo;
  RJsonValue * ret;
  rsize i, nodes;

  if ((ret = r_json_array_new ()) == NULL)
    return NULL;
  if ((topo = r_sys_topology_discover ()) == NULL)
    return ret;

  for (i = 0, nodes = r_sys_topology_node_count (topo); i < nodes; i++) {
    RSysNode * node = r_sys_topology_node (topo, i);

    if (node != NULL) {
      _json_append (ret, _json_node (topo, node, nodes));
      r_sys_node_unref (node);
    }
  }

  r_sys_topology_unref (topo);

  return ret;
}

static int
_print_json (rboolean pretty)
{
  RJsonValue * doc;
  RBuffer * buf;
  rchar * str;
  rsize size;

  if ((doc = r_json_object_new ()) == NULL) {
    r_printerr ("out of memory\n");
    return 1;
  }

  _json_add (doc, "cpu", _json_counts ());
  _json_add (doc, "numa", _json_numa ());
  _json_add (doc, "topology", _json_topology ());

  buf = r_json_value_to_buffer (doc, pretty ? R_JSON_NOFLAGS : R_JSON_COMPACT,
      NULL);
  r_json_value_unref (doc);

  if (buf == NULL) {
    r_printerr ("failed to serialise the JSON document\n");
    return 1;
  }

  /* The buffer holds raw bytes, so print a NUL-terminated copy. */
  size = r_buffer_get_size (buf);
  if ((str = r_malloc (size + 1)) != NULL) {
    r_buffer_extract (buf, 0, str, size);
    str[size] = 0;
    r_print ("%s\n", str);
    r_free (str);
  }
  r_buffer_unref (buf);

  return 0;
}


/* ----- Plain-text output ------------------------------------------- */

static void
_print_cpuset (const rchar * name, rboolean (*fill) (RBitset * cpuset))
{
  RBitset * cpuset;
  rchar * str;

  if (!r_bitset_init_stack (cpuset, r_sys_cpuset_max ()) || !fill (cpuset)) {
    r_print ("  %-24s <unavailable>\n", name);
    return;
  }

  str = r_bitset_to_human_readable (cpuset);
  r_print ("  %-24s %s (%"RSIZE_FMT")\n", name, str != NULL ? str : "",
      r_bitset_popcount (cpuset));
  r_free (str);
}

static void
_print_counts (void)
{
  r_print ("CPU counts\n");
  r_print ("  %-24s %u\n", "packages", r_sys_cpu_packages ());
  r_print ("  %-24s %u\n", "physical cores", r_sys_cpu_physical_count ());
  r_print ("  %-24s %u\n", "logical CPUs", r_sys_cpu_logical_count ());
  r_print ("  %-24s %u\n", "allowed CPUs", r_sys_cpu_allowed_count ());
  r_print ("  %-24s %u\n", "max CPUs", r_sys_cpu_max_count ());

  r_print ("\nCPU sets\n");
  _print_cpuset ("possible", r_sys_cpuset_possible);
  _print_cpuset ("present", r_sys_cpuset_present);
  _print_cpuset ("online", r_sys_cpuset_online);
  _print_cpuset ("allowed", r_sys_cpuset_allowed);

  r_print ("\nNUMA nodes\n");
  r_print ("  %-24s %u\n", "nodes", r_sys_node_count ());
  r_print ("  %-24s %u\n", "with online CPUs",
      r_sys_node_count_with_online_cpus ());
  r_print ("  %-24s %u\n", "with allowed CPUs",
      r_sys_node_count_with_allowed_cpus ());
  r_print ("  %-24s ", "page placement");
  if (r_mem_numa_available ()) {
    rchar buf[32];
    r_print ("enforced, %s pages\n",
        _fmt_bytes (buf, sizeof (buf), r_mem_numa_page_size ()));
  } else {
    r_print ("not enforced by this platform\n");
  }
}

static void
_print_id (rsize id)
{
  if (id == R_SYS_ID_UNKNOWN)
    r_print ("%-5s", "?");
  else
    r_print ("%-5"RSIZE_FMT, id);
}

static void
_print_cpu (RSysCpu * cpu)
{
  RBitset * cpuset;
  rchar * str;
  rsize i, caches;
  ruint64 freqmin, freqmax;

  if (!r_bitset_init_stack (cpuset, r_sys_cpuset_max ()))
    return;

  r_print ("    cpu ");
  _print_id (r_sys_topology_cpu_id (cpu));
  r_print ("core ");
  _print_id (r_sys_topology_cpu_core_id (cpu));
  r_print ("pkg ");
  _print_id (r_sys_topology_cpu_package_id (cpu));

  freqmin = r_sys_topology_cpu_min_frequency (cpu);
  freqmax = r_sys_topology_cpu_max_frequency (cpu);
  if (freqmax > 0) {
    r_print ("%"RUINT64_FMT"-%"RUINT64_FMT" MHz  ", freqmin / 1000,
        freqmax / 1000);
  }

  if (r_sys_topology_cpu_siblings (cpu, cpuset)) {
    str = r_bitset_to_human_readable (cpuset);
    r_print ("siblings %s", str != NULL ? str : "");
    r_free (str);
  }
  r_print ("\n");

  for (i = 0, caches = r_sys_topology_cpu_cache_count (cpu); i < caches; i++) {
    RSysCpuCache cache;
    rchar buf[32];

    if (!r_sys_topology_cpu_cache (cpu, i, &cache))
      continue;

    r_print ("      L%u %-12s%10s", cache.level, _cache_type_str (cache.type),
        _fmt_bytes (buf, sizeof (buf), cache.size));
    if (cache.linesize > 0)
      r_print ("  %"RSIZE_FMT" B lines", cache.linesize);
    if (cache.ways > 0)
      r_print ("  %"RSIZE_FMT"-way", cache.ways);
    if (cache.sets > 0)
      r_print ("  %"RSIZE_FMT" sets", cache.sets);

    r_bitset_clear (cpuset);
    if (r_sys_topology_cpu_cache_cpuset (cpu, i, cpuset)) {
      str = r_bitset_to_human_readable (cpuset);
      r_print ("  shared %s", str != NULL ? str : "");
      r_free (str);
    }
    r_print ("\n");
  }
}

static void
_print_node_allocation (rsize id)
{
  rsize size = r_mem_numa_page_size ();
  ruint8 * mem;
  ruint got;

  r_print ("    allocation      ");
  if ((mem = r_mem_numa_alloc_onnode (size, (ruint)id)) == NULL) {
    r_print ("failed\n");
    return;
  }

  mem[0] = 1;
  if (r_mem_numa_node_of (mem, &got)) {
    r_print ("one page requested on node %"RSIZE_FMT", backed by node %u%s\n",
        id, got, got == id ? "" : " (not placed as asked)");
  } else {
    r_print ("one page on node %"RSIZE_FMT", placement not reportable here\n",
        id);
  }

  r_mem_numa_free (mem, size);
}

static void
_print_topology (void)
{
  RSysTopology * topo;
  rsize i, j, nodes;

  r_print ("\nTopology\n");
  if ((topo = r_sys_topology_discover ()) == NULL) {
    r_print ("  <discovery failed>\n");
    return;
  }

  if ((nodes = r_sys_topology_node_count (topo)) == 0)
    r_print ("  <no nodes discovered>\n");

  for (i = 0; i < nodes; i++) {
    RSysNode * node;
    RSysCpu * cpu;
    rsize id, cpus, total, avail;

    if ((node = r_sys_topology_node (topo, i)) == NULL)
      continue;

    id = r_sys_topology_node_id (node);
    cpus = r_sys_topology_node_cpu_count (node);
    total = r_sys_topology_node_total_memory (node);
    avail = r_sys_topology_node_available_memory (node);

    r_print ("  node %"RSIZE_FMT" - %"RSIZE_FMT" CPUs", id, cpus);
    if (total > 0) {
      rchar buf[32];
      r_print (", %s total", _fmt_bytes (buf, sizeof (buf), total));
    }
    if (avail > 0) {
      rchar buf[32];
      r_print (", %s free", _fmt_bytes (buf, sizeof (buf), avail));
    }
    r_print ("\n");

    r_print ("    distances      ");
    for (j = 0; j < nodes; j++) {
      RSysNode * other = r_sys_topology_node (topo, j);

      if (other != NULL) {
        r_print (" %"RSIZE_FMT":%"RSIZE_FMT, r_sys_topology_node_id (other),
            r_sys_topology_node_distance (node, r_sys_topology_node_id (other)));
        r_sys_node_unref (other);
      }
    }
    r_print ("\n");

    _print_node_allocation (id);

    for (j = 0; j < cpus; j++) {
      if ((cpu = r_sys_topology_node_cpu (node, j)) != NULL) {
        _print_cpu (cpu);
        r_sys_cpu_unref (cpu);
      }
    }

    r_sys_node_unref (node);
  }

  r_sys_topology_unref (topo);
}


/* ----- Entry point ------------------------------------------------- */

int
main (int argc, char ** argv)
{
  RArgParser * parser = r_arg_parser_new (NULL, "1.0");
  RArgParseCtx * ctx;
  RArgParseResult res;
  int ret = 0;
  const RArgOptionEntry entries[] = {
    { "json",   'j', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,
      "Emit a JSON document instead of the plain-text report", NULL, NULL },
    { "pretty", 'p', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,
      "Indent the JSON document instead of minifying it", NULL, NULL },
  };

  r_arg_parser_set_summary (parser,
      "Report the CPU, cache and NUMA topology of this machine, and which "
      "node a page allocation actually lands on.");
  r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries));

  if ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)) != NULL) {
    if (r_arg_parse_ctx_get_option_bool (ctx, "json")) {
      ret = _print_json (r_arg_parse_ctx_get_option_bool (ctx, "pretty"));
    } else {
      _print_counts ();
      _print_topology ();
    }

    r_arg_parse_ctx_unref (ctx);
  } else {
    r_arg_parser_print_error (parser, R_ARG_PARSE_FLAG_NONE);
    ret = -1;
  }

  r_arg_parser_unref (parser);

  return ret;
}
