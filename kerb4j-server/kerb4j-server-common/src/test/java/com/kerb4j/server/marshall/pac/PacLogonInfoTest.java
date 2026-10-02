package com.kerb4j.server.marshall.pac;

import com.kerb4j.server.marshall.Kerb4JException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

class PacLogonInfoTest {

    @Test
    void resourceGroupSidsUseResourceDomainSidExactlyOnce() throws Kerb4JException {
        // MS-PAC KERB_VALIDATION_INFO + MS-KILE domain local groups:
        // compressed resource group RelativeIds are expanded under ResourceGroupDomainSid once.
        PacSid resourceGroupDomainSid = sidWithSubs(21, 111, 222, 333);
        PacSid relativeResourceGroupRid = sidWithSubs(1234);
        PacSid fullResourceGroupSid = PacSid.append(resourceGroupDomainSid, relativeResourceGroupRid);

        PacSid[] resourceGroupSids = PacLogonInfo.extractGroupSids(new PacGroup[]{new PacGroup(fullResourceGroupSid, 0)});

        Assertions.assertEquals(1, resourceGroupSids.length);
        Assertions.assertEquals("S-1-5-21-111-222-333-1234", resourceGroupSids[0].toHumanReadableString());

        PacSid duplicateDomainAppendSid = PacSid.append(resourceGroupDomainSid, fullResourceGroupSid);
        Assertions.assertNotEquals(duplicateDomainAppendSid.toHumanReadableString(), resourceGroupSids[0].toHumanReadableString());
    }

    @Test
    void accountDomainGroupSidsStillCombineLogonDomainSidAndGroupIds() throws Kerb4JException {
        PacSid logonDomainSid = sidWithSubs(21, 111, 222, 333);
        PacSid relativeGroupRid = sidWithSubs(513);

        PacSid[] groupSids = PacLogonInfo.expandDomainGroupSids(new PacGroup[]{new PacGroup(relativeGroupRid, 0)}, logonDomainSid);

        Assertions.assertEquals(1, groupSids.length);
        Assertions.assertEquals("S-1-5-21-111-222-333-513", groupSids[0].toHumanReadableString());
    }

    @Test
    void allGroupSidsAreMergedInOrderWithoutDuplicates() throws Kerb4JException {
        PacSid accountDomainGroup = sidWithSubs(21, 111, 222, 333, 513);
        PacSid resourceDomainGroup = sidWithSubs(21, 444, 555, 666, 777);
        PacSid extraSid = sidWithSubs(21, 999, 888, 777, 1001);

        PacSid[] allGroupSids = PacLogonInfo.mergeGroupSids(
                new PacSid[]{accountDomainGroup, resourceDomainGroup},
                new PacSid[]{resourceDomainGroup},
                new PacSid[]{extraSid, accountDomainGroup});

        Assertions.assertEquals(3, allGroupSids.length);
        Assertions.assertEquals(accountDomainGroup, allGroupSids[0]);
        Assertions.assertEquals(resourceDomainGroup, allGroupSids[1]);
        Assertions.assertEquals(extraSid, allGroupSids[2]);
    }

    private static PacSid sidWithSubs(int... subAuthorities) throws Kerb4JException {
        ByteBuffer buffer = ByteBuffer.allocate(subAuthorities.length * 4).order(ByteOrder.LITTLE_ENDIAN);
        for (int subAuthority : subAuthorities) {
            buffer.putInt(subAuthority);
        }
        return PacSid.createFromSubs(buffer.array());
    }
}
