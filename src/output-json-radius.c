/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 * \author Eric Leblond <el@stamus-networks.com>
 *
 * RADIUS EVE JSON logger.
 */

#include "suricata-common.h"
#include "conf.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "output.h"
#include "output-json.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "output-json-radius.h"
#include "rust.h"

typedef struct LogRadiusCtx_ {
    OutputJsonCtx *eve_ctx;
    bool log_credentials;
    bool only_promoted_fields;
    char *hoist_csv;
} LogRadiusCtx;

typedef struct LogRadiusThreadCtx_ {
    LogRadiusCtx *radiuslog_ctx;
    OutputJsonThreadCtx *thread;
} LogRadiusThreadCtx;

static int JsonRadiusLogger(ThreadVars *tv, void *thread_data,
        const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    LogRadiusThreadCtx *thread = thread_data;

    JsonBuilder *js = CreateEveHeader((Packet *)p, 0, "radius", NULL, thread->radiuslog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    SCRadiusLogJson(tx, js, thread->radiuslog_ctx->log_credentials,
            thread->radiuslog_ctx->hoist_csv, thread->radiuslog_ctx->only_promoted_fields);

    OutputJsonBuilderBuffer(js, thread->thread);
    jb_free(js);

    return TM_ECODE_OK;
}

static void OutputRadiusLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogRadiusCtx *radiuslog_ctx = (LogRadiusCtx *)output_ctx->data;
    if (radiuslog_ctx->hoist_csv != NULL) {
        SCFree(radiuslog_ctx->hoist_csv);
    }
    SCFree(radiuslog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputRadiusLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };

    LogRadiusCtx *radiuslog_ctx = SCCalloc(1, sizeof(*radiuslog_ctx));
    if (unlikely(radiuslog_ctx == NULL)) {
        return result;
    }
    radiuslog_ctx->eve_ctx = parent_ctx->data;
    radiuslog_ctx->log_credentials = true;

    if (conf != NULL) {
        const char *val = ConfNodeLookupChildValue(conf, "log-credentials");
        if (val != NULL && strcasecmp(val, "no") == 0) {
            radiuslog_ctx->log_credentials = false;
        }

        if (ConfNodeChildValueIsTrue(conf, "only-promoted-fields")) {
            radiuslog_ctx->only_promoted_fields = true;
        }

        ConfNode *fields = ConfNodeLookupChild(conf, "fields");
        if (fields != NULL) {
            size_t total = 0;
            ConfNode *field;
            TAILQ_FOREACH (field, &fields->head, next) {
                if (field->val == NULL) {
                    continue;
                }
                total += strlen(field->val) + 1; /* +1 for ',' or trailing NUL */
            }
            if (total > 0) {
                radiuslog_ctx->hoist_csv = SCCalloc(1, total);
                if (radiuslog_ctx->hoist_csv == NULL) {
                    SCFree(radiuslog_ctx);
                    return result;
                }
                char *p = radiuslog_ctx->hoist_csv;
                TAILQ_FOREACH (field, &fields->head, next) {
                    if (field->val == NULL) {
                        continue;
                    }
                    if (p != radiuslog_ctx->hoist_csv) {
                        *p++ = ',';
                    }
                    size_t len = strlen(field->val);
                    memcpy(p, field->val, len);
                    p += len;
                }
                *p = '\0';
            }
        }
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(radiuslog_ctx);
        return result;
    }
    output_ctx->data = radiuslog_ctx;
    output_ctx->DeInit = OutputRadiusLogDeInitCtxSub;

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_RADIUS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonRadiusLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogRadiusThreadCtx *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }
    LogRadiusCtx *ctx = ((OutputCtx *)initdata)->data;
    thread->radiuslog_ctx = ctx;
    thread->thread = CreateEveThreadCtx(t, ctx->eve_ctx);
    if (thread->thread == NULL) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }
    *data = (void *)thread;
    return TM_ECODE_OK;
}

static TmEcode JsonRadiusLogThreadDeinit(ThreadVars *t, void *data)
{
    LogRadiusThreadCtx *thread = (LogRadiusThreadCtx *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->thread);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonRadiusLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonRadiusLog", "eve-log.radius",
            OutputRadiusLogInitSub, ALPROTO_RADIUS, JsonRadiusLogger, JsonRadiusLogThreadInit,
            JsonRadiusLogThreadDeinit, NULL);
}
